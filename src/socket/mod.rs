use std::{io, mem, net::SocketAddr, os::fd::RawFd};

use tokio::net::{ToSocketAddrs, lookup_host};

mod control_message;
mod l2tp;
mod udp;

async fn each_addr<A: ToSocketAddrs, F, T>(addr: A, mut f: F) -> io::Result<T>
where
    F: FnMut(&SocketAddr) -> io::Result<T>,
{
    let mut last_err = None;
    for addr in lookup_host(addr).await? {
        match f(&addr) {
            Ok(l) => return Ok(l),
            Err(e) => last_err = Some(e),
        }
    }

    match last_err {
        Some(err) => Err(err),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )),
    }
}

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

unsafe fn setsockopt<T>(
    fd: RawFd,
    opt: libc::c_int,
    val: libc::c_int,
    payload: T,
) -> io::Result<()> {
    let payload = &raw const payload as *const _;
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as libc::socklen_t,
    ))
    .map(|_| ())
}

pub use l2tp::L2tpSocket;
pub use udp::{IpPacketInfo, UdpReceiver, UdpSocket};
