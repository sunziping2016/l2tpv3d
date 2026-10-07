use std::{
    cell::RefCell,
    collections::VecDeque,
    future::poll_fn,
    io,
    iter::{self, repeat_with},
    marker::PhantomData,
    pin::{Pin, pin},
    task::Poll,
    time::Duration,
};

use better_tokio_select::tokio_select;
use futures::{
    FutureExt, StreamExt, TryFutureExt,
    future::{self, Fuse, FusedFuture, MaybeDone},
};
use thiserror::Error;
use tokio::{
    sync::{Notify, mpsc},
    time::Sleep,
};
use tokio_util::time::{DelayQueue, delay_queue};

#[derive(Debug, Clone)]
pub struct Header {
    pub conn_id: u32,
    pub ns: u16,
    pub nr: u16,
}

#[derive(Debug, Clone)]
pub struct Message<M> {
    pub header: Header,
    /// None indicates an explicit ACK.
    pub body: Option<M>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("message retransmission timeout")]
    RetransmissionTimeout,
    #[error("invalid Nr received")]
    InvalidNr,
    #[error("connection idle")]
    Idle,
}

pub trait Codec {
    type Payload;

    /// Return None to drop the message.
    ///
    /// Message drop should only happen in the following cases:
    /// 1.  control header failure: message too short, T/L/S bits set to 0, mismatched version,
    ///     invalid length. Note connection ID is usually handled in the multiplexing layer.
    /// 2.  digest failure: missing digest when authentication is required, or
    ///     digest verification failed if a digest is present.
    fn decode_and_verify(&self, out: &[u8]) -> Option<Message<Self::Payload>>;

    // Extend the buf with message encoded.
    fn encode_and_sign(&self, buf: &mut Vec<u8>, msg: Message<&Self::Payload>);
}

pub trait Transport {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>>;
    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>>;
}

pub struct RetransmissionPolicy {
    base_interval: Duration,
    max_interval: Duration,
    limit: u32,
}

impl RetransmissionPolicy {
    pub const fn new(base_interval: Duration, max_interval: Duration, limit: u32) -> Self {
        assert!(!base_interval.is_zero());
        assert!(!max_interval.is_zero());
        assert!(limit > 0);
        Self {
            base_interval,
            max_interval,
            limit,
        }
    }

    fn next(&self, retransmit_times: u32) -> Option<Duration> {
        if retransmit_times >= self.limit {
            return None;
        }
        if retransmit_times >= u32::BITS {
            return Some(self.max_interval);
        }
        Some(
            self.base_interval
                .checked_mul(1 << retransmit_times)
                .map_or(self.max_interval, |x| x.min(self.max_interval)),
        )
    }

    fn full_interval(&self) -> Duration {
        let mut n = 0;
        iter::from_fn(move || {
            let ret = self.next(n)?;
            n += 1;
            Some(ret)
        })
        .sum()
    }
}

struct DriverConfig {
    receive_window_size: u16,
    peer_receive_window_size: u16,
    peer_connection_id: u32,
    retransmission_policy: RetransmissionPolicy,
    idle_timeout: Duration,
    ack_pending: bool,
}

tokio::task_local! {
    static DRIVER_CONFIG: RefCell<DriverConfig>;
}

#[derive(Clone)]
pub struct Sender<'a, M> {
    sender_tx: mpsc::Sender<M>,
    idle_reset_notify: &'a Notify,
    // 'a is modeling DRIVER_CONFIG lifetime
    _phantom: PhantomData<&'a ()>,
}

impl<'a, M> Sender<'a, M> {
    /// Send a message to the peer.
    pub async fn send(&self, msg: M) {
        let _ = self.sender_tx.send(msg).await;
    }

    pub async fn reset_idle_timer(&self) {
        self.idle_reset_notify.notify_one();
    }

    /// Set the peer receive window size
    ///
    /// This method panics if `value` is zero.
    pub fn set_peer_receive_window_size(&self, value: u16) {
        assert_ne!(value, 0);
        DRIVER_CONFIG.with(move |cfg| {
            cfg.borrow_mut().peer_receive_window_size = value;
        });
    }

    pub fn set_peer_connection_id(&self, value: u32) {
        DRIVER_CONFIG.with(move |cfg| {
            cfg.borrow_mut().peer_connection_id = value;
        });
    }

    pub fn set_retransmission_policy(&self, value: RetransmissionPolicy) {
        DRIVER_CONFIG.with(move |cfg| {
            cfg.borrow_mut().retransmission_policy = value;
        });
    }
}

pub struct Receiver<M> {
    receiver_rx: mpsc::Receiver<Result<M, Error>>,
}

impl<M> Receiver<M> {
    pub async fn recv(&mut self) -> Result<M, Error> {
        self.receiver_rx
            .recv()
            .await
            .expect("driver dropped while recv")
    }
}

pub struct ControlConnection<T, C> {
    conn: T,
    codec: C,
    config: DriverConfig,
}

const DEFAULT_RETRANSMISSION_POLICY: RetransmissionPolicy =
    RetransmissionPolicy::new(Duration::from_secs(1), Duration::from_secs(8), 10);
const DEFAULT_WINDOW_SIZE: u16 = 4;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

impl<T, C> ControlConnection<T, C> {
    pub const fn new(conn: T, codec: C) -> Self {
        Self {
            conn,
            codec,
            config: DriverConfig {
                receive_window_size: DEFAULT_WINDOW_SIZE,
                peer_receive_window_size: DEFAULT_WINDOW_SIZE,
                peer_connection_id: 0,
                retransmission_policy: DEFAULT_RETRANSMISSION_POLICY,
                idle_timeout: DEFAULT_IDLE_TIMEOUT,
                ack_pending: false,
            },
        }
    }
}

impl<T, C> ControlConnection<T, C> {
    pub const fn retransmission_policy(mut self, value: RetransmissionPolicy) -> Self {
        self.config.retransmission_policy = value;
        self
    }

    pub const fn peer_connection_id(mut self, value: u32) -> Self {
        self.config.peer_connection_id = value;
        self
    }

    pub fn receive_window_size(mut self, value: u16) -> Self {
        assert_ne!(value, 0);
        self.config.receive_window_size = value;
        self
    }

    pub fn peer_receive_window_size(mut self, value: u16) -> Self {
        assert_ne!(value, 0);
        self.config.peer_receive_window_size = value;
        self
    }

    pub fn idle_timeout(mut self, value: Duration) -> Self {
        assert!(!value.is_zero());
        self.config.idle_timeout = value;
        self
    }

    /// handler must do cleanup when receiving RetransmissionTimeout
    /// It must send a Hello when receiving Idle.
    /// It may use some statistics info to detect busy data channel to reset Idle timer.
    /// It must send a StopCCN when receive InvalidNr or other malformed or invalid message.
    pub async fn run<O>(
        self,
        handler: impl AsyncFnOnce(Sender<C::Payload>, Receiver<C::Payload>) -> O,
    ) -> O
    where
        T: Transport,
        C: Codec,
    {
        let (sender_tx, sender_rx) = mpsc::channel(1);
        let (receiver_tx, receiver_rx) = mpsc::channel(1);
        let idle_reset_notify = Notify::new();
        let sender = Sender {
            sender_tx,
            idle_reset_notify: &idle_reset_notify,
            _phantom: PhantomData,
        };
        let receiver = Receiver { receiver_rx };
        let handler = pin!(future::maybe_done(handler(sender, receiver)));
        let exit_timer = pin!(future::Fuse::terminated());
        let idle_timer = pin!(future::Fuse::terminated());
        let driver = Driver {
            conn: self.conn,
            codec: self.codec,
            ns: 0,
            nr: 0,
            recv_queue: VecDeque::new(),
            reorder_buffer: VecDeque::new(),
            send_buffer: Vec::new(),
            recv_buffer: vec![0u8; u16::MAX as usize],
            peer_nr: 0,
            unacked_messages: VecDeque::new(),
            handler,
            rx: sender_rx,
            tx: receiver_tx,
            retransmit_timers: DelayQueue::new(),
            exit_timer,
            idle_timer,
            idle_reset_notify: &idle_reset_notify,
        };
        DRIVER_CONFIG
            .scope(RefCell::new(self.config), driver.run())
            .await
    }
}
struct UnackedMessage<M> {
    retransmit_times: u32,
    key: Option<delay_queue::Key>,
    msg: M,
}

struct Driver<'a, T, C, M, H: Future> {
    conn: T,
    codec: C,

    ns: u16,
    nr: u16,

    recv_queue: VecDeque<Result<M, Error>>,
    send_buffer: Vec<u8>,
    recv_buffer: Vec<u8>,

    reorder_buffer: VecDeque<Option<M>>,

    peer_nr: u16,
    unacked_messages: VecDeque<UnackedMessage<M>>,

    handler: Pin<&'a mut MaybeDone<H>>,

    rx: mpsc::Receiver<M>,
    tx: mpsc::Sender<Result<M, Error>>,
    retransmit_timers: DelayQueue<u16>,
    exit_timer: Pin<&'a mut Fuse<Sleep>>,
    idle_timer: Pin<&'a mut Fuse<Sleep>>,
    idle_reset_notify: &'a Notify,
}

impl<'a, T, C, M, H: Future> Driver<'a, T, C, M, H> {
    fn on_transport_received(&mut self, size: usize)
    where
        C: Codec<Payload = M>,
    {
        let buf = &self.recv_buffer[..size];
        let Message { header, body } = match self.codec.decode_and_verify(buf) {
            Some(inner) => inner,
            None => return,
        };

        if let n = header.nr.wrapping_sub(self.peer_nr)
            && n != 0
        {
            if n <= self.unacked_messages.len() as u16 {
                self.peer_nr = header.nr;
                for _ in 0..n {
                    let msg = self.unacked_messages.pop_front().unwrap();
                    if let Some(key) = msg.key {
                        self.retransmit_timers.remove(&key);
                    }
                }
            } else if n <= 32768 {
                self.recv_queue.push_back(Err(Error::InvalidNr));
                return;
            }
        }
        self.reset_idle_timer();
        DRIVER_CONFIG.with(|cfg| {
            if let Some(body) = body {
                match header.ns.wrapping_sub(self.nr) {
                    0 => {
                        self.nr = self.nr.wrapping_add(1);
                        self.recv_queue.push_back(Ok(body));
                        self.reorder_buffer.pop_front();
                        while let Some(msg) =
                            self.reorder_buffer.pop_front_if(|x| x.is_some()).flatten()
                        {
                            self.nr = self.nr.wrapping_add(1);
                            self.recv_queue.push_back(Ok(msg));
                        }
                        cfg.borrow_mut().ack_pending = true;
                    }
                    n @ 1..=32767 => {
                        if DRIVER_CONFIG.with(|cfg| n >= cfg.borrow().receive_window_size) {
                            return;
                        }
                        let n = n as usize;
                        if n >= self.reorder_buffer.len() {
                            self.reorder_buffer.extend(
                                repeat_with(|| None).take(n + 1 - self.reorder_buffer.len()),
                            );
                        }
                        self.reorder_buffer[n] = Some(body);
                    }
                    // old or duplicate
                    _ => cfg.borrow_mut().ack_pending = true,
                }
            }
        });
    }

    fn on_ack_notified(&mut self)
    where
        C: Codec,
    {
        debug_assert!(self.send_buffer.is_empty());
        DRIVER_CONFIG.with(|cfg| {
            let mut cfg = cfg.borrow_mut();
            cfg.ack_pending = false;
            self.codec.encode_and_sign(
                &mut self.send_buffer,
                Message {
                    header: Header {
                        conn_id: cfg.peer_connection_id,
                        ns: self.ns,
                        nr: self.nr,
                    },
                    body: None,
                },
            );
        });
    }

    fn on_sending_msg(&mut self, msg: M)
    where
        C: Codec<Payload = M>,
    {
        debug_assert!(self.send_buffer.is_empty());
        let ns = self.ns;
        self.ns = self.ns.wrapping_add(1);
        DRIVER_CONFIG.with(|cfg| {
            let mut cfg = cfg.borrow_mut();
            cfg.ack_pending = false;
            self.codec.encode_and_sign(
                &mut self.send_buffer,
                Message {
                    header: Header {
                        conn_id: cfg.peer_connection_id,
                        ns,
                        nr: self.nr,
                    },
                    body: Some(&msg),
                },
            );
            let interval = cfg
                .retransmission_policy
                .next(0)
                .expect("retransmission policy limit should be > 0");
            let key = self.retransmit_timers.insert(ns, interval);
            self.unacked_messages.push_back(UnackedMessage {
                retransmit_times: 0,
                key: Some(key),
                msg,
            });
        });
    }

    fn on_message_timer_expired(&mut self, expired: delay_queue::Expired<u16>)
    where
        C: Codec<Payload = M>,
    {
        debug_assert!(self.send_buffer.is_empty());
        let ns = expired.into_inner();
        let msg = &mut self.unacked_messages[ns.wrapping_sub(self.peer_nr) as usize];
        DRIVER_CONFIG.with(|cfg| {
            let mut cfg = cfg.borrow_mut();
            cfg.ack_pending = false;
            self.codec.encode_and_sign(
                &mut self.send_buffer,
                Message {
                    header: Header {
                        conn_id: cfg.peer_connection_id,
                        ns,
                        nr: self.nr,
                    },
                    body: Some(&msg.msg),
                },
            );
            msg.retransmit_times += 1;
            msg.key = match cfg.retransmission_policy.next(msg.retransmit_times) {
                Some(interval) => Some(self.retransmit_timers.insert(ns, interval)),
                None => {
                    self.recv_queue.push_back(Err(Error::RetransmissionTimeout));
                    None
                }
            };
        });
    }

    fn reset_idle_timer(&mut self) {
        self.idle_timer
            .set(tokio::time::sleep(DRIVER_CONFIG.with(|cfg| cfg.borrow().idle_timeout)).fuse());
    }

    async fn run(mut self) -> H::Output
    where
        T: Transport,
        C: Codec<Payload = M>,
        H: Future,
    {
        let mut ack_ready = pin!(poll_fn(|_cx| {
            DRIVER_CONFIG.with(|cfg| {
                if cfg.borrow().ack_pending {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
        }));
        self.reset_idle_timer();
        loop {
            tokio_select!(
                biased,
                match .. {
                    // We use biased select to prefer piggyback.
                    // tokio budget can help us to ensure that ack_ready always has a chance to run.

                    // GROUP 1: those set ack_pending and make group 2 ready to poll
                    .. if let Ok(size) = self.conn.recv(self.recv_buffer.as_mut_slice())
                        && self.recv_queue.is_empty() =>
                    {
                        self.on_transport_received(size);
                    }
                    .. if let _ = self.conn.send(self.send_buffer.as_slice())
                        && !self.send_buffer.is_empty() =>
                    {
                        self.send_buffer.clear();
                    }

                    // GROUP 2: those clear ack_pending
                    .. if let Ok(_) = self.tx.reserve().map_ok(|x| {
                        x.send(self.recv_queue.pop_front().unwrap());
                    }) && !self.recv_queue.is_empty() => {}
                    .. if let _ = self.handler.as_mut()
                        && !self.handler.is_terminated() =>
                    {
                        self.exit_timer.set(
                            tokio::time::sleep(
                                DRIVER_CONFIG
                                    .with(|cfg| cfg.borrow().retransmission_policy.full_interval()),
                            )
                            .fuse(),
                        );
                    }
                    .. if let Some(msg) = self.rx.recv()
                        && self.send_buffer.is_empty()
                        && DRIVER_CONFIG.with(|cfg| self.unacked_messages.len()
                            < cfg.borrow().peer_receive_window_size as usize) =>
                    {
                        self.on_sending_msg(msg);
                    }
                    .. if let Some(expired) = self.retransmit_timers.next()
                        && self.send_buffer.is_empty() =>
                    {
                        self.on_message_timer_expired(expired);
                    }
                    .. if let _ = self.idle_timer.as_mut()
                        && !self.idle_timer.is_terminated() =>
                    {
                        self.recv_queue.push_back(Err(Error::Idle));
                    }
                    .. if let _ = self.idle_reset_notify.notified() => {
                        self.reset_idle_timer();
                    }

                    // GROUP 3: reading ack_pending
                    .. if let _ = ack_ready.as_mut()
                        && self.send_buffer.is_empty() =>
                    {
                        self.on_ack_notified();
                    }

                    // Exits
                    .. if let _ = self.exit_timer.as_mut()
                        && !self.exit_timer.is_terminated() =>
                    {
                        return self.handler.as_mut().take_output().unwrap();
                    }
                }
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, io::Write};

    use futures::FutureExt;
    use rand::{RngExt, SeedableRng};
    use tokio::net::UnixDatagram;
    use tracing::{Instrument, Level};

    use crate::test_utils::*;

    use super::*;

    struct MockCodec;

    impl Transport for UnixDatagram {
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.recv(buf).await
        }
        async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.send(buf).await
        }
    }

    impl Codec for MockCodec {
        type Payload = u32;
        fn decode_and_verify(&self, out: &[u8]) -> Option<Message<Self::Payload>> {
            if out.len() < 8 {
                return None;
            }
            let connection_id = u32::from_be_bytes(out[0..4].try_into().unwrap());
            let ns = u16::from_be_bytes(out[4..6].try_into().unwrap());
            let nr = u16::from_be_bytes(out[6..8].try_into().unwrap());
            let body = if out.len() < 12 {
                None
            } else {
                Some(u32::from_be_bytes(out[8..12].try_into().unwrap()))
            };
            let msg = Message {
                header: Header {
                    conn_id: connection_id,
                    ns,
                    nr,
                },
                body,
            };
            tracing::debug!(msg = ?msg, "received");
            Some(msg)
        }

        fn encode_and_sign(&self, buf: &mut Vec<u8>, msg: Message<&Self::Payload>) {
            tracing::info!(msg = ?msg, "sending ");
            buf.write_all(&msg.header.conn_id.to_be_bytes()).unwrap();
            buf.write_all(&msg.header.ns.to_be_bytes()).unwrap();
            buf.write_all(&msg.header.nr.to_be_bytes()).unwrap();
            if let Some(msg) = msg.body {
                buf.write_all(&msg.to_be_bytes()).unwrap();
            }
        }
    }

    fn require_send<T: Send>(value: T) -> T {
        value
    }

    #[tokio::test(start_paused = true)]
    async fn test_simple_pair() {
        // FIXME: tokio auto-advance's timer is unreliable since v1.50.0
        //   https://github.com/tokio-rs/tokio/issues/8232
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_timer(tokio_uptime())
            .init();
        let (sock1, sock3) = UnixDatagram::pair().unwrap();
        let (sock2, sock4) = UnixDatagram::pair().unwrap();
        let fut1 = pin!(require_send(
            ControlConnection::new(sock1, MockCodec)
                .run(async |tx, mut rx| {
                    tx.send(1).await;
                    assert_eq!(rx.recv().await.unwrap(), 2);
                    assert_eq!(rx.recv().await.unwrap(), 3);
                    tx.send(4).await;
                    tracing::info!("done");
                })
                .then(|_| async {
                    tracing::info!("all done");
                })
                .instrument(tracing::info_span!("sock", id = 0))
        ));
        let fut2 = pin!(require_send(
            ControlConnection::new(sock2, MockCodec)
                .run(async |tx, mut rx| {
                    assert_eq!(rx.recv().await.unwrap(), 1);
                    tx.send(2).await;
                    tx.send(3).await;
                    assert_eq!(rx.recv().await.unwrap(), 4);
                    tracing::info!("done");
                })
                .then(|_| async {
                    tracing::info!("all done");
                })
                .instrument(tracing::info_span!("sock", id = 1))
        ));
        let rng = RefCell::new(rand::rngs::StdRng::seed_from_u64(2));
        let fut3 = pin!(async {
            let mut buf = vec![0u8; 1500];
            while let Ok(size) = sock3.recv(buf.as_mut_slice()).await {
                if rng.borrow_mut().random_ratio(60, 100) {
                    continue;
                }
                let _ = sock4.send(&buf[..size]).await;
            }
        });
        let fut4 = pin!(async {
            let mut buf = vec![0u8; 1500];
            while let Ok(size) = sock4.recv(buf.as_mut_slice()).await {
                if rng.borrow_mut().random_ratio(60, 100) {
                    continue;
                }
                let _ = sock3.send(&buf[..size]).await;
            }
        });
        future::join(future::select(fut1, fut3), future::select(fut2, fut4)).await;
    }
}
