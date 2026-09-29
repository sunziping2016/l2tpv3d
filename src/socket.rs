use std::{
    io,
    mem::{self, MaybeUninit},
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    slice,
};

use socket2::{SockAddr, SockAddrStorage, Socket, Type};
use tokio::{
    io::unix::AsyncFd,
    net::{ToSocketAddrs, lookup_host},
};

macro_rules! each_addr {
    ($addr:expr, |$arg:ident| $body:expr) => {{
        let mut last_err = None;
        for $arg in $addr {
            match $body {
                Ok(l) => return Ok(l),
                Err(e) => last_err = Some(e),
            }
        }
        match last_err {
            Some(err) => Err(err),
            None => Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "could not resolve to any addresses",
                )
            })),
        }
    }};
}

pub struct L2tpSocket {
    inner: AsyncFd<Socket>,
}

impl L2tpSocket {
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        conn_id: u32,
        interface: Option<&[u8]>,
    ) -> io::Result<Self> {
        each_addr!(lookup_host(addr).await?, |addr| {
            let addr = l2tp_sockaddr(addr, conn_id);
            let sock = Socket::new(
                addr.domain(),
                Type::DGRAM.nonblocking(),
                Some(IPPROTO_L2TP.into()),
            )?;
            if let Some(interface) = interface {
                sock.bind_device(Some(interface))?;
            }
            sock.bind(&addr)?;
            Ok(Self {
                inner: AsyncFd::new(sock)?,
            })
        })
    }

    pub async fn connect<A: ToSocketAddrs>(&self, addr: A, conn_id: u32) -> io::Result<()> {
        each_addr!(lookup_host(addr).await?, |addr| {
            let addr = l2tp_sockaddr(addr, conn_id);
            self.inner.get_ref().connect(&addr)
        })
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let buf = unsafe {
            slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len())
        };
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
                Ok(result) => {
                    return result.map(|(size, addr)| {
                        (
                            size,
                            addr.as_socket()
                                .expect("invalid ss_family returned from kernel"),
                        )
                    });
                }
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let buf = unsafe {
            slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len())
        };
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub fn device(&self) -> io::Result<Option<Vec<u8>>> {
        self.inner.get_ref().device()
    }
}

impl AsFd for L2tpSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl AsRawFd for L2tpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

// from <linux/in.h>
const IPPROTO_L2TP: libc::c_int = 115;

#[repr(C)]
struct SockaddrL2tpIp {
    l2tp_family: libc::sa_family_t,
    l2tp_unused: u16,
    l2tp_addr: libc::in_addr,
    l2tp_conn_id: u32,
    __pad: [u8; 4],
}

#[repr(C)]
struct SockaddrL2tpIp6 {
    l2tp_family: libc::sa_family_t,
    l2tp_unused: u16,
    l2tp_flowinfo: u32,
    l2tp_addr: libc::in6_addr,
    l2tp_scope_id: u32,
    l2tp_conn_id: u32,
}

fn l2tp_sockaddr(addr: SocketAddr, conn_id: u32) -> SockAddr {
    let mut storage = SockAddrStorage::zeroed();
    let len = match addr {
        SocketAddr::V4(addr) => {
            let storage = unsafe { storage.view_as::<SockaddrL2tpIp>() };
            storage.l2tp_family = libc::AF_INET as libc::sa_family_t;
            storage.l2tp_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            };
            storage.l2tp_conn_id = conn_id;
            mem::size_of::<SockaddrL2tpIp>() as libc::socklen_t
        }
        SocketAddr::V6(addr) => {
            let storage = unsafe { storage.view_as::<SockaddrL2tpIp6>() };
            storage.l2tp_family = libc::AF_INET6 as libc::sa_family_t;
            storage.l2tp_flowinfo = addr.flowinfo();
            storage.l2tp_addr = libc::in6_addr {
                s6_addr: addr.ip().octets(),
            };
            storage.l2tp_scope_id = addr.scope_id();
            storage.l2tp_conn_id = conn_id;
            mem::size_of::<SockaddrL2tpIp6>() as libc::socklen_t
        }
    };
    unsafe { SockAddr::new(storage, len) }
}
