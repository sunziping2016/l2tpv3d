use std::{mem, ptr};

#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub(crate) enum ControlMessageKind {
    Ipv4PacketInfo,
    Ipv6PacketInfo,
}

impl ControlMessageKind {
    const fn len(self) -> usize {
        match self {
            ControlMessageKind::Ipv4PacketInfo => mem::size_of::<libc::in_pktinfo>(),
            ControlMessageKind::Ipv6PacketInfo => mem::size_of::<libc::in6_pktinfo>(),
        }
    }
    const fn cmsg_space(self) -> usize {
        unsafe { libc::CMSG_SPACE(self.len() as libc::c_uint) as usize }
    }
    const fn cmsg_len(self) -> usize {
        unsafe { libc::CMSG_LEN(self.len() as libc::c_uint) as usize }
    }
    const fn cmsg_type(self) -> libc::c_int {
        match self {
            ControlMessageKind::Ipv4PacketInfo => libc::IP_PKTINFO,
            ControlMessageKind::Ipv6PacketInfo => libc::IPV6_PKTINFO,
        }
    }
    const fn cmsg_level(self) -> libc::c_int {
        match self {
            ControlMessageKind::Ipv4PacketInfo => libc::IPPROTO_IP,
            ControlMessageKind::Ipv6PacketInfo => libc::IPPROTO_IPV6,
        }
    }
    const fn header(self) -> libc::cmsghdr {
        libc::cmsghdr {
            cmsg_len: self.cmsg_len(),
            cmsg_level: self.cmsg_level(),
            cmsg_type: self.cmsg_type(),
        }
    }
}

pub(crate) const fn control_message_spaces(msgs: &[ControlMessageKind]) -> usize {
    let mut size = 0;
    let mut i = 0;
    while i < msgs.len() {
        size += msgs[i].cmsg_space();
        i += 1;
    }
    size
}

pub(crate) const fn max_control_message_space(msgs: &[&[ControlMessageKind]]) -> usize {
    let mut max_size = 0;
    let mut i = 0;
    while i < msgs.len() {
        let size = control_message_spaces(msgs[i]);
        if size > max_size {
            max_size = size;
        }
        i += 1;
    }
    max_size
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub(crate) enum ControlMessage<'a> {
    Ipv4PacketInfo(&'a libc::in_pktinfo),
    Ipv6PacketInfo(&'a libc::in6_pktinfo),
}

impl<'a> ControlMessage<'a> {
    fn kind(&self) -> ControlMessageKind {
        match self {
            ControlMessage::Ipv4PacketInfo(_) => ControlMessageKind::Ipv4PacketInfo,
            ControlMessage::Ipv6PacketInfo(_) => ControlMessageKind::Ipv6PacketInfo,
        }
    }
    unsafe fn encode_data(&self, dst: *mut u8) {
        match *self {
            ControlMessage::Ipv4PacketInfo(info) => unsafe {
                ptr::copy_nonoverlapping(
                    info as *const _ as *const u8,
                    dst,
                    mem::size_of_val(info),
                );
            },
            ControlMessage::Ipv6PacketInfo(info) => unsafe {
                ptr::copy_nonoverlapping(
                    info as *const _ as *const u8,
                    dst,
                    mem::size_of_val(info),
                );
            },
        }
    }
}

pub(crate) fn write_control_messages<'a>(buf: &'a mut [u8], msgs: &[ControlMessage]) -> &'a [u8] {
    // Create a dummy header so that we can use libc functions.
    // Sadly, socket2 doesn't provide API for us to write control messages with its msghdr wrapper.
    let mut chdr: libc::msghdr = unsafe { mem::zeroed() };
    chdr.msg_control = buf.as_mut_ptr() as *mut _;
    chdr.msg_controllen = buf.len();
    let mut last = None;
    let mut size = 0;
    for msg in msgs {
        let hdr = match last {
            None => unsafe { libc::CMSG_FIRSTHDR(&chdr) },
            Some(last) => unsafe { libc::CMSG_NXTHDR(&chdr, last) },
        };
        assert!(!hdr.is_null(), "buffer too small");
        last = Some(hdr);
        let kind = msg.kind();
        assert!(
            (hdr as usize)
                .checked_add(kind.cmsg_space())
                .is_some_and(|x| x <= buf.as_ptr_range().end as usize),
            "buffer too small"
        );
        size = hdr as usize + kind.cmsg_space() - buf.as_ptr_range().start as usize;
        unsafe {
            *hdr = kind.header();
            msg.encode_data(libc::CMSG_DATA(hdr));
        };
    }
    &buf[..size]
}

pub(crate) struct ControlMessageIterator<'a> {
    chdr: libc::msghdr,
    last: Option<*mut libc::cmsghdr>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> ControlMessageIterator<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        let mut chdr: libc::msghdr = unsafe { mem::zeroed() };
        chdr.msg_control = buf.as_ptr() as *mut _;
        chdr.msg_controllen = buf.len();
        Self {
            chdr,
            last: None,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a> Iterator for ControlMessageIterator<'a> {
    type Item = ControlMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let hdr = match self.last {
            None => unsafe { libc::CMSG_FIRSTHDR(&self.chdr) },
            Some(last) => unsafe { libc::CMSG_NXTHDR(&self.chdr, last) },
        };
        if hdr.is_null() {
            return None;
        }
        self.last = Some(hdr);
        match (unsafe { (*hdr).cmsg_level }, unsafe { (*hdr).cmsg_type }) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                if (hdr as usize)
                    .checked_add(ControlMessageKind::Ipv4PacketInfo.cmsg_len())
                    .is_some_and(|x| x <= self.chdr.msg_control as usize + self.chdr.msg_controllen)
                {
                    return Some(ControlMessage::Ipv4PacketInfo(unsafe {
                        &*(libc::CMSG_DATA(hdr) as *const libc::in_pktinfo)
                    }));
                }
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                if (hdr as usize)
                    .checked_add(ControlMessageKind::Ipv6PacketInfo.cmsg_len())
                    .is_some_and(|x| x <= self.chdr.msg_control as usize + self.chdr.msg_controllen)
                {
                    return Some(ControlMessage::Ipv6PacketInfo(unsafe {
                        &*(libc::CMSG_DATA(hdr) as *const libc::in6_pktinfo)
                    }));
                }
            }
            _ => return self.next(),
        };
        None
    }
}
