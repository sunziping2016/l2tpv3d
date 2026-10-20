use std::{
    collections::{HashMap, hash_map},
    io::{self, IoSlice},
    mem::MaybeUninit,
    net::{SocketAddr, SocketAddrV4},
    ops::Deref,
    os::fd::AsRawFd,
    slice,
    sync::{Arc, Mutex},
};

use better_tokio_select::tokio_select;
use socket2::{MaybeUninitSlice, MsgHdr, MsgHdrMut, SockAddr, Socket, Type};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc,
};
use tracing::error;

use super::control_message::{
    ControlMessage, ControlMessageKind, max_control_message_space, write_control_messages,
};

struct Msg {
    buf: Vec<u8>,
    peer: SockAddr,
    pkt_info: IpPacketInfo,
}

pub struct UdpSocket {
    socket: AsyncFd<Socket>,
    receivers: Mutex<HashMap<u32, mpsc::Sender<Msg>>>,
}

const CMSG_MAX_SIZE: usize = max_control_message_space(&[
    &[ControlMessageKind::Ipv4PacketInfo],
    &[ControlMessageKind::Ipv6PacketInfo],
]);

impl UdpSocket {
    pub fn bind(
        addr: SocketAddr,
        interface: Option<&[u8]>,
        only_v6: Option<bool>,
    ) -> io::Result<Self> {
        let is_ipv6 = matches!(&addr, SocketAddr::V6(_));
        let addr = SockAddr::from(addr);
        let socket = Socket::new(addr.domain(), Type::DGRAM.nonblocking(), None)?;
        if let Some(interface) = interface {
            socket.bind_device(Some(interface))?;
        }
        if is_ipv6 {
            if let Some(only_v6) = only_v6 {
                socket.set_only_v6(only_v6)?;
            }
            unsafe {
                super::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVPKTINFO,
                    true as libc::c_int,
                )?
            };
        } else {
            unsafe {
                super::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    true as libc::c_int,
                )?
            };
        }
        socket.bind(&addr)?;
        Ok(Self {
            socket: AsyncFd::new(socket)?,
            receivers: Mutex::new(HashMap::new()),
        })
    }

    fn do_listen(&self, conn_id: u32) -> io::Result<mpsc::Receiver<Msg>> {
        let (tx, rx) = mpsc::channel(128);
        let mut receivers = self.receivers.lock().unwrap();
        match receivers.entry(conn_id) {
            hash_map::Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "connection id already exists",
                ));
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(tx);
            }
        }
        Ok(rx)
    }

    pub fn listen(&self, conn_id: u32) -> io::Result<UdpReceiver<&Self>> {
        Ok(UdpReceiver {
            socket: self,
            conn_id,
            rx: self.do_listen(conn_id)?,
        })
    }

    pub fn listen_owned(self: Arc<Self>, conn_id: u32) -> io::Result<UdpReceiver<Arc<Self>>> {
        let rx = self.do_listen(conn_id)?;
        Ok(UdpReceiver {
            socket: self.clone(),
            conn_id,
            rx,
        })
    }

    pub async fn send(
        &self,
        buf: &[u8],
        peer: SocketAddr,
        local: Option<&IpPacketInfo>,
    ) -> io::Result<usize> {
        let peer = SockAddr::from(peer);
        let buf = [IoSlice::new(buf)];
        let mut ctl_buf = [0u8; CMSG_MAX_SIZE];
        let mut msg = MsgHdr::new().with_addr(&peer).with_buffers(&buf);
        if let Some(local) = local {
            let ctl = match local {
                IpPacketInfo::Ipv4(info) => {
                    write_control_messages(&mut ctl_buf, &[ControlMessage::Ipv4PacketInfo(info)])
                }
                IpPacketInfo::Ipv6(info) => {
                    write_control_messages(&mut ctl_buf, &[ControlMessage::Ipv6PacketInfo(info)])
                }
            };
            msg = msg.with_control(ctl);
        }
        self.socket
            .async_io(Interest::WRITABLE, |x| x.sendmsg(&msg, 0))
            .await
    }

    async fn recv(
        &self,
        buf: &mut [u8],
        peer: &mut SockAddr,
        pkt_info: &mut IpPacketInfo,
    ) -> io::Result<usize> {
        let buf = unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut _, buf.len()) };
        let mut control_buf = [MaybeUninit::uninit(); CMSG_MAX_SIZE];
        let mut buf = [MaybeUninitSlice::new(buf)];
        let mut msg = MsgHdrMut::new()
            .with_addr(peer)
            .with_buffers(&mut buf)
            .with_control(&mut control_buf);
        let size = self
            .socket
            .async_io(Interest::READABLE, |x| x.recvmsg(&mut msg, 0))
            .await?;
        if msg.flags().is_truncated() {
            return Err(io::Error::other("received packet was truncated"));
        }
        // socket2 doesn't provide a way to check MSG_CTRUNC.
        // Anyway, we can inspect the control buffer to determine if it was truncated.
        let control_len = msg.control_len();
        let control_buf = unsafe { control_buf[..control_len].assume_init_ref() };
        let mut has_pkt_info = false;
        for cmsg in super::control_message::ControlMessageIterator::new(control_buf) {
            match cmsg {
                ControlMessage::Ipv4PacketInfo(in_pktinfo) => {
                    *pkt_info = IpPacketInfo::Ipv4(*in_pktinfo);
                    has_pkt_info = true;
                }
                ControlMessage::Ipv6PacketInfo(in6_pktinfo) => {
                    *pkt_info = IpPacketInfo::Ipv6(*in6_pktinfo);
                    has_pkt_info = true;
                }
            }
        }
        if !has_pkt_info {
            return Err(io::Error::other("control data was truncated"));
        }
        Ok(size)
    }

    async fn run(&self) {
        let buf = &mut [0u8; 65535];
        let mut peer = SockAddr::from(SocketAddr::V4(SocketAddrV4::new([0, 0, 0, 0].into(), 0)));
        let mut pkt_info = IpPacketInfo::Ipv4(libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr { s_addr: 0 },
        });
        loop {
            tokio_select!(match .. {
                .. if let result = self.recv(buf, &mut peer, &mut pkt_info) => {
                    match result {
                        Ok(size) => {
                            if size < 8 {
                                continue;
                            }
                            let buf = &buf[..size];
                            let conn_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                            // dispatch by connection id
                            if let Some(receiver) = self.receivers.lock().unwrap().get(&conn_id) {
                                let _ = receiver.try_send(Msg {
                                    buf: buf.to_vec(),
                                    peer: peer.clone(),
                                    pkt_info: pkt_info.clone(),
                                });
                            }
                        }
                        Err(e) => {
                            error!(err = ?e, "failed to invoke recv()");
                        }
                    }
                }
            })
        }
    }

    pub async fn run_owned(self: Arc<Self>) {
        self.run().await
    }
}

#[derive(Clone, Debug)]
pub enum IpPacketInfo {
    Ipv4(libc::in_pktinfo),
    Ipv6(libc::in6_pktinfo),
}

pub struct UdpReceiver<T: Deref<Target = UdpSocket>> {
    socket: T,
    conn_id: u32,
    rx: mpsc::Receiver<Msg>,
}

impl<T: Deref<Target = UdpSocket>> UdpReceiver<T> {
    pub async fn recv(&mut self) -> Vec<u8> {
        self.rx.recv().await.expect("socket dropped").buf
    }
    pub async fn recv_from(&mut self) -> (Vec<u8>, SocketAddr, IpPacketInfo) {
        let msg = self.rx.recv().await.expect("socket dropped");
        (msg.buf, msg.peer.as_socket().unwrap(), msg.pkt_info)
    }
}

impl<T: Deref<Target = UdpSocket>> Drop for UdpReceiver<T> {
    fn drop(&mut self) {
        let mut receivers = self.socket.receivers.lock().unwrap();
        receivers.remove(&self.conn_id);
    }
}
