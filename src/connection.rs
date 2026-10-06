use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    iter::repeat_with,
    marker::PhantomData,
    pin::pin,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use better_tokio_select::tokio_select;
use futures::{
    FutureExt, StreamExt,
    future::{self, FusedFuture},
};
use thiserror::Error;
use tokio::{sync::mpsc, time::Instant};
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
    #[error("invalid Nr")]
    InvalidNr,
    #[error("send/recv error")]
    Io(io::Error),
}

pub trait Codec {
    type Payload;

    /// Return None to drop the message.
    ///
    /// Message drop should only happen in the following cases:
    /// 1.  control header failure: message too short, T/L/S bits set to 0, mismatched version,
    ///     invalid length, or mismatched connection ID. Mismatched connection ID is
    ///     unlikely to happen, since it should have been demultiplexed.
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

pub trait RetransmissionPolicy {
    fn next(&self, current: Duration) -> Duration;
}

#[derive(Debug, Clone)]
pub struct CappedExponentialBackoff {
    base: Duration,
    cap: Duration,
    linear_base: Duration,
}
impl CappedExponentialBackoff {
    pub const fn new(base: Duration, cap: Duration) -> Self {
        assert!(!base.is_zero());
        assert!(!cap.is_zero());
        let n = cap.as_nanos().div_ceil(base.as_nanos());
        assert!(n <= u32::MAX as u128);
        let n = n as u32;
        let linear_base = base
            .checked_mul(n.next_power_of_two() - 1)
            .expect("overflow when multiplying duration by scalar");
        Self {
            base,
            cap,
            linear_base,
        }
    }
    pub const fn base(&self) -> Duration {
        self.base
    }
    pub const fn cap(&self) -> Duration {
        self.cap
    }
}

impl RetransmissionPolicy for CappedExponentialBackoff {
    fn next(&self, current: Duration) -> Duration {
        if current >= self.linear_base {
            let n = u32::try_from((current - self.linear_base).as_nanos() / self.cap.as_nanos())
                .expect("overflow");
            return self.cap * (n + 1) + self.linear_base;
        }
        let n = u32::try_from(current.as_nanos() / self.base.as_nanos()).expect("overflow");
        self.base * ((n + 2).next_power_of_two() - 1)
    }
}

struct DriverConfig<R> {
    receive_window_size: u16,
    peer_receive_window_size: u16,
    peer_connection_id: u32,
    retransmission_policy: R,
    timeout: Duration,
}

pub struct Sender<'a, M, R> {
    sender_tx: mpsc::Sender<M>,
    config: &'a Mutex<DriverConfig<R>>,
}

impl<'a, M, R> Sender<'a, M, R> {
    /// Send a message to the peer.
    pub async fn send(&self, msg: M) {
        // [TODO] add a reserve() method for select!
        let _ = self.sender_tx.send(msg).await;
    }

    /// Set the peer receive window size
    ///
    /// This method panics if `value` is zero.
    pub fn set_peer_receive_window_size(&self, value: u16) {
        assert_ne!(value, 0);
        self.config.lock().unwrap().peer_receive_window_size = value;
    }
    pub fn set_peer_connection_id(&self, value: u32) {
        self.config.lock().unwrap().peer_connection_id = value;
    }

    /// Set the retransmission intervals.
    ///
    /// `value` should be a monotonically increasing sequence.
    /// If the driver hasn't received the acknowledgement of the peer, it will retransmit
    /// the message at the given intervals. When the driver misses retransmission ticks,
    /// an immediate retransmission happens, and the missed ticks will be skipped.
    ///
    /// The last interval is the timeout. If the driver hasn't received the acknowledgement for
    /// that interval, it will send a [`RetransmissionTimeout`] error through the receiver channel.
    ///
    /// This method panics when `value` is an empty vector.
    ///
    /// [`RetransmissionTimeout`]: Error::RetransmissionTimeout
    pub fn set_retransmission_intervals(&self, value: R) {
        self.config.lock().unwrap().retransmission_policy = value;
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

pub struct ControlConnection<T, C, R, M> {
    conn: T,
    codec: C,
    config: DriverConfig<R>,
    _phantom: PhantomData<M>,
}

impl<T, C, M> ControlConnection<T, C, CappedExponentialBackoff, M> {
    pub const fn new(conn: T, codec: C) -> Self {
        Self {
            conn,
            codec,
            config: DriverConfig {
                receive_window_size: Self::DEFAULT_WINDOW_SIZE,
                peer_receive_window_size: Self::DEFAULT_WINDOW_SIZE,
                peer_connection_id: 0,
                retransmission_policy: Self::DEFAULT_RETRANSMISSION_POLICY,
                timeout: Self::DEFAULT_TIMEOUT,
            },
            _phantom: PhantomData,
        }
    }
    pub const fn retransmission_base_interval(mut self, value: Duration) -> Self {
        let policy = &self.config.retransmission_policy;
        self.config.retransmission_policy = CappedExponentialBackoff::new(value, policy.cap());
        self
    }
    pub const fn retransmission_max_interval(mut self, value: Duration) -> Self {
        let policy = &self.config.retransmission_policy;
        self.config.retransmission_policy = CappedExponentialBackoff::new(policy.base(), value);
        self
    }
}

impl<T, C, R, M> ControlConnection<T, C, R, M> {
    const DEFAULT_RETRANSMISSION_POLICY: CappedExponentialBackoff =
        CappedExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(8));
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(63);
    const DEFAULT_WINDOW_SIZE: u16 = 4;

    pub const fn peer_connection_id(mut self, value: u32) -> Self {
        self.config.peer_connection_id = value;
        self
    }

    pub fn retransmission_policy<R1>(self, value: R1) -> ControlConnection<T, C, R1, M> {
        let ControlConnection {
            conn,
            codec,
            config,
            _phantom,
        } = self;
        let DriverConfig {
            receive_window_size,
            peer_receive_window_size,
            peer_connection_id,
            retransmission_policy: _,
            timeout,
        } = config;
        ControlConnection {
            conn,
            codec,
            config: DriverConfig {
                receive_window_size,
                peer_receive_window_size,
                peer_connection_id,
                retransmission_policy: value,
                timeout,
            },
            _phantom,
        }
    }

    pub fn timeout(mut self, value: Duration) -> Self {
        self.config.timeout = value;
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

    pub async fn run<O>(
        self,
        handler: impl AsyncFnOnce(Sender<C::Payload, R>, Receiver<C::Payload>) -> O,
    ) -> O
    where
        T: Transport,
        C: Codec<Payload = M>,
        R: RetransmissionPolicy,
    {
        let config = Mutex::new(self.config);

        let (sender_tx, sender_rx) = mpsc::channel(1);
        let (receiver_tx, receiver_rx) = mpsc::channel(1);
        let sender = Sender {
            sender_tx,
            config: &config,
        };
        let receiver = Receiver { receiver_rx };

        let driver = Driver {
            conn: self.conn,
            codec: self.codec,
            config: &config,
            ns: 0,
            nr: 0,
            recv_queue: VecDeque::new(),
            reorder_buffer: VecDeque::new(),
            send_buffer: Vec::new(),
            peer_nr: 0,
            unacked_messages: VecDeque::new(),
            ack_pending: PollFlag::default(),
        };
        driver
            .run(handler(sender, receiver), sender_rx, receiver_tx)
            .await
    }
}

enum SeqClass {
    Expected,
    Future(u16),
    OldOrDuplicate,
}

fn classify_ns(ns: u16, expected: u16) -> SeqClass {
    match ns.wrapping_sub(expected) {
        0 => SeqClass::Expected,
        n @ 1..=32767 => SeqClass::Future(n),
        _ => SeqClass::OldOrDuplicate,
    }
}

struct UnackedMessage<M> {
    queued_at: Instant,
    key: Option<delay_queue::Key>,
    msg: M,
}

#[derive(Default)]
struct PollFlag(AtomicBool);

impl PollFlag {
    fn set(&self) {
        self.0.store(true, Ordering::Release);
    }
    fn clear(&self) {
        self.0.store(false, Ordering::Release);
    }
    async fn ready(&self) {
        poll_fn(|_cx| {
            if self.0.swap(false, Ordering::AcqRel) {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await
    }
}

struct Driver<'a, T, C, M, R> {
    conn: T,
    codec: C,
    config: &'a Mutex<DriverConfig<R>>,

    ns: u16,
    nr: u16,

    recv_queue: VecDeque<Result<M, Error>>,
    send_buffer: Vec<u8>,

    reorder_buffer: VecDeque<Option<M>>,

    peer_nr: u16,
    unacked_messages: VecDeque<UnackedMessage<M>>,
    ack_pending: PollFlag,
}

impl<'a, T, C, M, R> Driver<'a, T, C, M, R> {
    fn on_transport_received(
        &mut self,
        result: io::Result<&[u8]>,
        retransmit_timers: &mut DelayQueue<u16>,
    ) where
        C: Codec<Payload = M>,
    {
        let buf = match result {
            Ok(buf) => buf,
            Err(e) => {
                self.recv_queue.push_back(Err(Error::Io(e)));
                return;
            }
        };
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
                        retransmit_timers.remove(&key);
                    }
                }
            } else if n <= 32768 {
                self.recv_queue.push_back(Err(Error::InvalidNr));
                return;
            }
        }

        // process NS
        if let Some(body) = body {
            match classify_ns(header.ns, self.nr) {
                SeqClass::Expected => {
                    self.nr = self.nr.wrapping_add(1);
                    self.recv_queue.push_back(Ok(body));
                    self.reorder_buffer.pop_front();
                    while let Some(msg) =
                        self.reorder_buffer.pop_front_if(|x| x.is_some()).flatten()
                    {
                        self.nr = self.nr.wrapping_add(1);
                        self.recv_queue.push_back(Ok(msg));
                    }
                    self.ack_pending.set();
                }
                SeqClass::Future(n) => {
                    if n >= self.config.lock().unwrap().receive_window_size {
                        return;
                    }
                    let n = n as usize;
                    if n >= self.reorder_buffer.len() {
                        self.reorder_buffer
                            .extend(repeat_with(|| None).take(n + 1 - self.reorder_buffer.len()));
                    }
                    self.reorder_buffer[n] = Some(body);
                }
                SeqClass::OldOrDuplicate => self.ack_pending.set(),
            }
        }
    }

    fn on_ack_notified(&mut self)
    where
        C: Codec,
    {
        debug_assert!(self.send_buffer.is_empty());
        self.codec.encode_and_sign(
            &mut self.send_buffer,
            Message {
                header: Header {
                    conn_id: self.config.lock().unwrap().peer_connection_id,
                    ns: self.ns,
                    nr: self.nr,
                },
                body: None,
            },
        );
    }

    fn on_message_received(&mut self, msg: M, queue: &mut DelayQueue<u16>)
    where
        C: Codec<Payload = M>,
        R: RetransmissionPolicy,
    {
        debug_assert!(self.send_buffer.is_empty());
        let ns = self.ns;
        self.ns = self.ns.wrapping_add(1);
        self.ack_pending.clear();
        self.codec.encode_and_sign(
            &mut self.send_buffer,
            Message {
                header: Header {
                    conn_id: self.config.lock().unwrap().peer_connection_id,
                    ns,
                    nr: self.nr,
                },
                body: Some(&msg),
            },
        );
        let now = Instant::now();
        let interval = self
            .config
            .lock()
            .unwrap()
            .retransmission_policy
            .next(Duration::ZERO);
        let key = queue.insert_at(ns, now + interval);
        self.unacked_messages.push_back(UnackedMessage {
            queued_at: now,
            key: Some(key),
            msg,
        });
    }

    fn on_message_timer_expired(
        &mut self,
        expired: delay_queue::Expired<u16>,
        queue: &mut DelayQueue<u16>,
    ) where
        C: Codec<Payload = M>,
        R: RetransmissionPolicy,
    {
        debug_assert!(self.send_buffer.is_empty());
        let ns = expired.into_inner();
        let msg = &mut self.unacked_messages[ns.wrapping_sub(self.peer_nr) as usize];
        self.ack_pending.clear();
        self.codec.encode_and_sign(
            &mut self.send_buffer,
            Message {
                header: Header {
                    conn_id: self.config.lock().unwrap().peer_connection_id,
                    ns,
                    nr: self.nr,
                },
                body: Some(&msg.msg),
            },
        );
        let now = Instant::now();
        let interval = now - msg.queued_at;
        let config = self.config.lock().unwrap();
        msg.key = if interval >= config.timeout {
            self.recv_queue.push_back(Err(Error::RetransmissionTimeout));
            None
        } else {
            Some(
                queue.insert_at(
                    ns,
                    msg.queued_at
                        + config
                            .retransmission_policy
                            .next(interval)
                            .min(config.timeout),
                ),
            )
        };
    }

    async fn run<H>(
        mut self,
        handler: H,
        mut sender_rx: mpsc::Receiver<M>,
        receiver_tx: mpsc::Sender<Result<M, Error>>,
    ) -> H::Output
    where
        T: Transport,
        C: Codec<Payload = M>,
        H: Future,
        R: RetransmissionPolicy,
    {
        let mut buffer = vec![0u8; u16::MAX as usize];
        let mut retransmit_timers = DelayQueue::new();
        let mut handler = pin!(future::maybe_done(handler));
        let mut exit_timer = pin!(future::Fuse::terminated());

        loop {
            tokio_select!(
                biased,
                match .. {
                    .. if let result = self.conn.recv(buffer.as_mut_slice())
                        && self.recv_queue.is_empty() =>
                    {
                        self.on_transport_received(
                            result.map(|x| &buffer[..x]),
                            &mut retransmit_timers,
                        );
                    }
                    .. if let _ = self.conn.send(self.send_buffer.as_slice())
                        && !self.send_buffer.is_empty() =>
                    {
                        self.send_buffer.clear();
                    }

                    .. if let _ = handler.as_mut()
                        && !handler.is_terminated() =>
                    {
                        exit_timer
                            .set(tokio::time::sleep(self.config.lock().unwrap().timeout).fuse());
                    }
                    .. if let Ok(permit) = receiver_tx.reserve()
                        && !self.recv_queue.is_empty() =>
                    {
                        permit.send(self.recv_queue.pop_front().unwrap());
                    }
                    .. if let Some(msg) = sender_rx.recv()
                        && self.send_buffer.is_empty()
                        && self.unacked_messages.len()
                            < self.config.lock().unwrap().peer_receive_window_size as usize =>
                    {
                        self.on_message_received(msg, &mut retransmit_timers);
                    }

                    .. if let Some(expired) = retransmit_timers.next()
                        && self.send_buffer.is_empty() =>
                    {
                        self.on_message_timer_expired(expired, &mut retransmit_timers);
                    }
                    .. if let _ = exit_timer.as_mut()
                        && !exit_timer.is_terminated() =>
                    {
                        return handler.take_output().unwrap();
                    }

                    .. if let _ = self.ack_pending.ready()
                        && self.send_buffer.is_empty() =>
                    {
                        self.on_ack_notified();
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

    #[test]
    fn test_classify_seq_num() {
        // Example in RFC3931 section 4.2:
        //
        // > if the last received sequence number was 15, then messages with sequence numbers
        // > 0 through 15, as well as 32784 through 65535, would be considered less than or equal.
        // > Such a message would be considered a duplicate of a message...
        //
        // when last received sequence number was 15, the expected sequence number is 16.
        assert!(matches!(classify_ns(15, 16), SeqClass::OldOrDuplicate));
        assert!(matches!(classify_ns(32784, 16), SeqClass::OldOrDuplicate));
        assert!(matches!(classify_ns(32783, 16), SeqClass::Future(_)));
        assert!(matches!(classify_ns(17, 16), SeqClass::Future(1)));
        assert!(matches!(classify_ns(16, 16), SeqClass::Expected));
    }

    #[test]
    fn test_exponential_backoff() {
        #[allow(clippy::type_complexity)]
        let table: &[(u64, u64, &[(u64, u64)])] = &[
            (
                2,
                10,
                &[
                    // backoff=2s
                    (0, 2),
                    (1, 2),
                    // backoff=4s
                    (2, 6),
                    (5, 6),
                    // backoff=8s
                    (6, 14),
                    (13, 14),
                    // backoff=10s
                    (14, 24),
                    (23, 24),
                    // backoff=10s
                    (24, 34),
                    (33, 34),
                    (34, 44),
                ],
            ),
            (3, 6, &[(2, 3), (3, 9), (8, 9), (9, 15)]),
            (3, 5, &[(2, 3), (3, 8), (7, 8), (8, 13)]),
            (3, 7, &[(2, 3), (3, 9), (8, 9), (9, 16)]),
        ];
        for (base, cap, table) in table.iter().cloned() {
            let backoff =
                CappedExponentialBackoff::new(Duration::from_secs(base), Duration::from_secs(cap));
            for (query, answer) in table.iter().cloned() {
                assert_eq!(
                    backoff.next(Duration::from_secs(query)),
                    Duration::from_secs(answer),
                    "backoff at {}s when base={}s cap={}s",
                    query,
                    base,
                    cap,
                );
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
