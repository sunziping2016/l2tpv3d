use std::{borrow::Cow, range::Range};

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use rand::CryptoRng;
use sha1::Sha1;
use smallvec::SmallVec;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MessageType(pub u16);

impl MessageType {
    // RFC3931 section 3.1
    pub const SCCRQ: Self = Self(1);
    pub const SCCRP: Self = Self(2);
    pub const SCCCN: Self = Self(3);
    pub const STOPCCN: Self = Self(4);
    pub const HELLO: Self = Self(6);
    pub const ACK: Self = Self(20);
    pub const OCRQ: Self = Self(7);
    pub const OCRP: Self = Self(8);
    pub const OCCN: Self = Self(9);
    pub const ICRQ: Self = Self(10);
    pub const ICRP: Self = Self(11);
    pub const ICCN: Self = Self(12);
    pub const CDN: Self = Self(14);
    pub const WEN: Self = Self(15);
    pub const SLI: Self = Self(16);

    pub const fn type_id(self) -> (VendorId, MessageType) {
        (VendorId::IETF, self)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VendorId(pub u16);

impl VendorId {
    pub const IETF: Self = Self(0);
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AttributeType(pub u16);

impl AttributeType {
    // RFC3931 section 5.4
    pub const MESSAGE_TYPE: Self = Self(0);
    pub const RESULT_CODE: Self = Self(1);
    pub const TIE_BREAKER: Self = Self(5);
    pub const HOST_NAME: Self = Self(7);
    pub const VENDOR_NAME: Self = Self(8);
    pub const RECEIVE_WINDOW_SIZE: Self = Self(10);
    pub const SERIAL_NUMBER: Self = Self(15);
    pub const PHYSICAL_CHANNEL_ID: Self = Self(25);
    pub const CIRCUIT_ERRORS: Self = Self(34);
    pub const RANDOM_VECTOR: Self = Self(36);
    pub const EXTENDED_VEND_ID: Self = Self(58);
    pub const MESSAGE_DIGEST: Self = Self(59);
    pub const ROUTER_ID: Self = Self(60);
    pub const ASSIGNED_CONTROL_CONNECTION_ID: Self = Self(61);
    pub const PSEUDOWIRE_CAPABILITIES_LIST: Self = Self(62);
    pub const LOCAL_SESSION_ID: Self = Self(63);
    pub const REMOTE_SESSION_ID: Self = Self(64);
    pub const ASSIGNED_COOKIE: Self = Self(65);
    pub const REMOTE_END_ID: Self = Self(66);
    pub const PSEUDOWIRE_TYPE: Self = Self(68);
    pub const L2_SPECIIFIC_SUBLAYER: Self = Self(69);
    pub const DATA_SEQUENCING: Self = Self(70);
    pub const CIRCUIT_STATUS: Self = Self(71);
    pub const PREFERRED_LANGUAGE: Self = Self(72);
    pub const CONTROL_MESSAGE_AUTHENTICATION_NONCE: Self = Self(73);
    pub const TX_CONNECT_SPEED: Self = Self(74);
    pub const RX_CONNECT_SPEED: Self = Self(75);

    pub const fn id(self) -> (VendorId, AttributeType) {
        (VendorId::IETF, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Avp<T> {
    pub vendor_id: VendorId,
    pub r#type: AttributeType,
    pub value: T,
    pub mandatory: bool,
    pub hidden: bool,
}

impl<T> Avp<T> {
    fn map<U, F>(self, f: F) -> Avp<U>
    where
        F: FnOnce(T) -> U,
    {
        Avp {
            vendor_id: self.vendor_id,
            r#type: self.r#type,
            value: f(self.value),
            mandatory: self.mandatory,
            hidden: self.hidden,
        }
    }

    pub fn id(&self) -> (VendorId, AttributeType) {
        (self.vendor_id, self.r#type)
    }
}

impl Avp<MessageType> {
    pub fn type_id(&self) -> (VendorId, MessageType) {
        (self.vendor_id, self.value)
    }
}

impl<T> Avp<T> {
    pub fn extend_to_vec(&self, buf: &mut Vec<u8>)
    where
        T: AsRef<[u8]>,
    {
        let value = self.value.as_ref();
        let length = AVP_HEADER_LEN + value.len();
        if length > AVP_LENGTH_MASK as usize {
            panic!("AVP length exceeds maximum");
        }
        buf.reserve(length);
        let mut flags_and_length = length as u16;
        if self.mandatory {
            flags_and_length |= M_BIT;
        }
        if self.hidden {
            flags_and_length |= H_BIT;
        }
        buf.extend_from_slice(&flags_and_length.to_be_bytes());
        buf.extend_from_slice(&self.vendor_id.0.to_be_bytes());
        buf.extend_from_slice(&self.r#type.0.to_be_bytes());
        buf.extend_from_slice(value);
    }
}

#[derive(Error, Debug, Eq, PartialEq, Clone)]
pub enum Error {
    #[error("malformed header")]
    MalformedHeader,

    #[error("malformed AVP")]
    MalformedAvp,

    #[error("missing or invalid digest")]
    InvalidDigest,

    #[error("missing hiding key")]
    MissingHidingKey,

    #[error("invalid hidden AVP")]
    InvalidHiddenAvp,
}

const ENCRYPT: bool = true;
const DECRYPT: bool = false;

fn do_hide<const MODE: bool>(value: &mut [u8], r#type: AttributeType, key: &[u8], vector: &[u8]) {
    let mut previous: Option<[u8; 16]> = None;
    for chunk in value.chunks_mut(16) {
        let mut md5 = Md5::default();
        match previous {
            None => {
                md5.update(r#type.0.to_be_bytes());
                md5.update(key);
                md5.update(vector);
            }
            Some(previous) => {
                md5.update(key);
                md5.update(previous);
            }
        }
        let mask = md5.finalize();
        if MODE == DECRYPT {
            previous = chunk.try_into().ok();
        }
        for (byte, mask_byte) in chunk.iter_mut().zip(mask) {
            *byte ^= mask_byte;
        }
        if MODE == ENCRYPT {
            previous = chunk.try_into().ok();
        }
    }
}

pub struct Key {
    hiding_key: SmallVec<[u8; 16]>,
    digest_key: SmallVec<[u8; 16]>,
}

impl Key {
    pub fn new(password: &[u8]) -> Self {
        let key = |extra: u8| -> [u8; 16] {
            Hmac::<Md5>::new_from_slice(password)
                .unwrap()
                .chain_update([extra])
                .finalize()
                .into_bytes()
                .into()
        };

        Self {
            hiding_key: SmallVec::from_buf(key(1)),
            digest_key: SmallVec::from_buf(key(2)),
        }
    }

    pub fn hiding_key(&self) -> &[u8] {
        &self.hiding_key
    }

    pub fn digest_key(&self) -> &[u8] {
        &self.digest_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub conn_id: u32,
    pub ns: u16,
    pub nr: u16,
}

const AVP_HEADER_LEN: usize = 6;
const AVP_LENGTH_MASK: u16 = 0x03ff;
const VERSION: u8 = 3;
const M_BIT: u16 = 0x8000;
const H_BIT: u16 = 0x4000;
const CONTROL_HEADER_LEN: usize = 12;
const CONTROL_FLAGS: u16 = 0xc800;

#[derive(Clone, Debug)]
struct RawDecoder<'a>(&'a [u8]);

impl<'a> RawDecoder<'a> {
    fn poll_header(&mut self) -> Result<Header, Error> {
        if self.0.len() < CONTROL_HEADER_LEN {
            return Err(Error::MalformedHeader);
        }
        let flags = u16::from_be_bytes([self.0[0], self.0[1]]);
        let length = usize::from(u16::from_be_bytes([self.0[2], self.0[3]]));
        if flags & (CONTROL_FLAGS | 0x0f) != CONTROL_FLAGS | u16::from(VERSION)
            || length != self.0.len()
        {
            return Err(Error::MalformedHeader);
        }
        let conn_id = u32::from_be_bytes([self.0[4], self.0[5], self.0[6], self.0[7]]);
        let ns = u16::from_be_bytes([self.0[8], self.0[9]]);
        let nr = u16::from_be_bytes([self.0[10], self.0[11]]);
        self.0 = &self.0[CONTROL_HEADER_LEN..];
        Ok(Header { conn_id, ns, nr })
    }

    fn poll_avp(&mut self) -> Result<Avp<&'a [u8]>, Error> {
        if self.0.len() < AVP_HEADER_LEN {
            return Err(Error::MalformedAvp);
        }
        let flags_and_length = u16::from_be_bytes([self.0[0], self.0[1]]);
        let length = usize::from(flags_and_length & AVP_LENGTH_MASK);
        if length < AVP_HEADER_LEN || length > self.0.len() {
            return Err(Error::MalformedAvp);
        }
        let mandatory = flags_and_length & M_BIT != 0;
        let hidden = flags_and_length & H_BIT != 0;
        let vendor_id = VendorId(u16::from_be_bytes([self.0[2], self.0[3]]));
        let r#type = AttributeType(u16::from_be_bytes([self.0[4], self.0[5]]));
        let value = &self.0[AVP_HEADER_LEN..length];
        self.0 = &self.0[length..];
        Ok(Avp {
            vendor_id,
            r#type,
            value,
            mandatory,
            hidden,
        })
    }
}

impl<'a> Iterator for RawDecoder<'a> {
    type Item = Result<Avp<&'a [u8]>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.0.is_empty()).then(|| self.poll_avp())
    }
}

#[derive(Copy, Clone)]
enum MessageDigest<'a> {
    Md5(&'a [u8]),
    Sha1(&'a [u8]),
}

impl<'a> MessageDigest<'a> {
    fn verify(self, buf: &[&[u8]], key: &[u8]) -> bool {
        match self {
            Self::Md5(tag) => {
                let mut hmac = Hmac::<Md5>::new_from_slice(key).unwrap();
                buf.iter().copied().for_each(|x| hmac.update(x));
                hmac.verify_slice(tag).is_ok()
            }
            Self::Sha1(tag) => {
                let mut hmac = Hmac::<Sha1>::new_from_slice(key).unwrap();
                buf.iter().copied().for_each(|x| hmac.update(x));
                hmac.verify_slice(tag).is_ok()
            }
        }
    }
}

struct Unhide<'a, 'b> {
    key: Option<&'a [u8]>,
    vector: Option<Cow<'b, [u8]>>,
}

impl<'a, 'b> Unhide<'a, 'b> {
    fn new(key: Option<&'a [u8]>) -> Self {
        Self { key, vector: None }
    }
    fn into_filter_mapper<T, U>(mut self) -> impl FnMut(Avp<T>) -> Option<Result<Avp<U>, Error>>
    where
        T: Into<Cow<'b, [u8]>>,
        U: From<Cow<'b, [u8]>>,
    {
        move |x| {
            self.process(x)
                .transpose()
                .map(|x| x.map(|x| x.map(U::from)))
        }
    }
    fn process<T>(&mut self, avp: Avp<T>) -> Result<Option<Avp<Cow<'b, [u8]>>>, Error>
    where
        T: Into<Cow<'b, [u8]>>,
    {
        if avp.id() == AttributeType::RANDOM_VECTOR.id() {
            (!avp.hidden).ok_or(Error::MalformedAvp)?;
            self.vector = Some(Into::<Cow<'b, [u8]>>::into(avp.value));
            return Ok(None);
        }
        if !avp.hidden {
            return Ok(Some(avp.map(|x| x.into())));
        }
        let vector = self.vector.as_ref().ok_or(Error::MalformedAvp)?;
        let key = self.key.ok_or(Error::MissingHidingKey)?;
        let mut value = Into::<Cow<'b, [u8]>>::into(avp.value);
        (value.len() >= 2).ok_or(Error::InvalidHiddenAvp)?;
        {
            let value = value.to_mut();
            do_hide::<DECRYPT>(value, avp.r#type, key, vector);
            let len = usize::from(u16::from_be_bytes([value[0], value[1]]));
            (len <= value.len() - 2).ok_or(Error::InvalidHiddenAvp)?;
            value.drain(..2);
            value.truncate(len);
        }
        Ok(Some(Avp {
            vendor_id: avp.vendor_id,
            r#type: avp.r#type,
            value,
            mandatory: avp.mandatory,
            hidden: avp.hidden,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message<T> {
    pub header: Header,
    pub body: Option<(Avp<MessageType>, Vec<Avp<T>>)>,
}

pub trait KeyProvider {
    fn keys(&self, avps: &[Avp<&[u8]>]) -> &[Key];
}

impl<T> KeyProvider for T
where
    T: AsRef<[Key]>,
{
    fn keys(&self, _avps: &[Avp<&[u8]>]) -> &[Key] {
        self.as_ref()
    }
}

pub fn decode_and_verify<'a, 'b, T, K>(
    buf: &'a [u8],
    keys: &'b K,
    local_nonce: &[u8],
    remote_nonce: &[u8],
) -> Result<(Message<T>, Option<&'b Key>), Error>
where
    T: From<Cow<'a, [u8]>>,
    K: KeyProvider + ?Sized,
{
    // decode
    let (header, avps) = {
        let mut dec = RawDecoder(buf);
        let header = dec.poll_header()?;
        let avps: SmallVec<[Avp<&'a [u8]>; 20]> = dec.collect::<Result<_, _>>()?;
        (header, avps)
    };
    let mut avps = avps.as_slice();
    if avps.is_empty() {
        keys.keys(avps).is_empty().ok_or(Error::InvalidDigest)?;
        return Ok((Message { header, body: None }, None));
    }

    // process message type
    let msg_type = &avps[0];
    (msg_type.r#type == AttributeType::MESSAGE_TYPE
        && !msg_type.hidden
        && msg_type.value.len() == 2)
        .ok_or(Error::MalformedAvp)?;
    let msg_type = msg_type
        .clone()
        .map(|x| MessageType(u16::from_be_bytes([x[0], x[1]])));
    avps = &avps[1..];

    // process digest
    let key = 'verify: {
        let mut tags = SmallVec::<[Range<usize>; 2]>::new();
        let mut known_digests = SmallVec::<[MessageDigest; 2]>::new();
        while tags.len() < 2
            && let Some(avp) = avps.first()
            && avp.id() == AttributeType::MESSAGE_DIGEST.id()
        {
            (!avp.hidden && !avp.value.is_empty()).ok_or(Error::MalformedAvp)?;
            let digest = &avp.value[1..];
            tags.push(buf.subslice_range(digest).unwrap());
            known_digests.extend(match avp.value[0] {
                0 => {
                    (avp.value.len() == 17).ok_or(Error::MalformedAvp)?;
                    Some(MessageDigest::Md5(digest))
                }
                1 => {
                    (avp.value.len() == 21).ok_or(Error::MalformedAvp)?;
                    Some(MessageDigest::Sha1(digest))
                }
                _ => {
                    (!avp.mandatory).ok_or(Error::MalformedAvp)?;
                    None
                }
            });
            avps = &avps[1..];
        }
        let keys = keys.keys(avps);
        if known_digests.is_empty() {
            keys.is_empty().ok_or(Error::InvalidDigest)?;
            break 'verify None;
        }
        let zeros = SmallVec::<[u8; 20]>::from_elem(
            0u8,
            tags.iter().map(|x| x.end - x.start).max().unwrap(),
        );
        let mut slices = SmallVec::<[&[u8]; 7]>::new();
        if keys.is_empty() || msg_type.type_id() == MessageType::SCCRQ.type_id() {
            // skip nonce
        } else if msg_type.type_id() == MessageType::SCCRP.type_id() {
            let remote_nonce = avps
                .iter()
                .find(|x| x.id() == AttributeType::CONTROL_MESSAGE_AUTHENTICATION_NONCE.id())
                // peer doesn't enable authentication?
                .ok_or(Error::InvalidDigest)?;
            (!remote_nonce.hidden).ok_or(Error::MalformedAvp)?;
            slices.push(remote_nonce.value);
            slices.push(local_nonce);
        } else {
            slices.push(remote_nonce);
            slices.push(local_nonce);
        }
        let mut offset = 0usize;
        for tag in tags {
            slices.push(&buf[offset..tag.start]);
            slices.push(&zeros[..tag.end - tag.start]);
            offset = tag.end;
        }
        slices.push(&buf[offset..]);
        for digest in known_digests {
            for key in keys {
                if digest.verify(&slices, &key.digest_key) {
                    break 'verify Some(key);
                }
            }
        }
        // [TODO]; check digest
        return Err(Error::InvalidDigest);
    };

    Ok((
        Message {
            header,
            body: Some((
                msg_type,
                avps.iter()
                    .cloned()
                    .filter_map(Unhide::new(key.map(|k| k.hiding_key())).into_filter_mapper())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
        },
        key,
    ))
}

enum DigestType {
    Md5,
    #[allow(unused)]
    Sha1,
}

impl DigestType {
    const fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
        }
    }
}

struct EncodeParams;

impl EncodeParams {
    const RANDOM_VECTOR_LEN: usize = 16;
    const DIGEST_TYPE: DigestType = DigestType::Md5;

    fn padding_len(attr: AttributeType) -> usize {
        if attr.0 == 456 {
            return 128;
        }
        0
    }
}

pub fn encode_and_sign<T>(
    buf: &mut Vec<u8>,
    msg: &Message<T>,
    key: Option<&Key>,
    local_nonce: &[u8],
    remote_nonce: &[u8],
) where
    T: AsRef<[u8]>,
{
    let mut rng = rand::rng();
    encode_and_sign_with_rng(buf, msg, key, local_nonce, remote_nonce, &mut rng);
}

pub fn encode_and_sign_with_rng<T, R>(
    buf: &mut Vec<u8>,
    msg: &Message<T>,
    key: Option<&Key>,
    local_nonce: &[u8],
    remote_nonce: &[u8],
    rng: &mut R,
) where
    T: AsRef<[u8]>,
    R: CryptoRng + ?Sized,
{
    buf.clear();

    // encode header
    // To further optimize the performance, we may compute the final length first.
    // But in practice, buf should have a very large capacity.
    buf.reserve(CONTROL_HEADER_LEN);
    buf.extend_from_slice(&(CONTROL_FLAGS | u16::from(VERSION)).to_be_bytes());
    const LEN_RANGE: Range<usize> = Range { start: 2, end: 4 };
    buf.extend_from_slice(&0u16.to_be_bytes()); // length, will fill later
    buf.extend_from_slice(&msg.header.conn_id.to_be_bytes());
    buf.extend_from_slice(&msg.header.ns.to_be_bytes());
    buf.extend_from_slice(&msg.header.nr.to_be_bytes());

    let (msg_type, avps) = match &msg.body {
        Some((msg_type, avps)) => (msg_type, avps.as_slice()),
        None => {
            if key.is_none() {
                *buf[LEN_RANGE].as_mut_array::<2>().unwrap() =
                    (CONTROL_HEADER_LEN as u16).to_be_bytes();
                return;
            }
            const ACK: Avp<MessageType> = Avp {
                vendor_id: VendorId::IETF,
                r#type: AttributeType::MESSAGE_TYPE,
                value: MessageType::ACK,
                mandatory: true,
                hidden: false,
            };
            (&ACK, &[][..])
        }
    };

    // encode msg type
    let msg_type_value = msg_type.value.0.to_be_bytes();
    assert!(!msg_type.hidden);
    msg_type
        .clone()
        .map(|_| &msg_type_value[..])
        .extend_to_vec(buf);

    // encode digest
    // RFC3931 allow two digests with two different passwords, but it doesn't provide a way
    // for the server side to tell which password is used as the hiding key.
    //
    // Therefore, let's send only one digest at the client side. The server will try matching
    // the digest against all available passwords until one succeeds, so as to know how to
    // handle the hidden AVPs.
    let digest_range = key.map(|_| {
        const ZEROS: [u8; 21] = [0; 21];
        let digest_len = EncodeParams::DIGEST_TYPE.digest_len();
        (Avp {
            vendor_id: VendorId::IETF,
            r#type: AttributeType::MESSAGE_DIGEST,
            value: &ZEROS[..(digest_len) + 1],
            mandatory: true,
            hidden: false,
        })
        .extend_to_vec(buf);
        let hash_type_pos = buf.len() - digest_len - 1;
        buf[hash_type_pos] = match EncodeParams::DIGEST_TYPE {
            DigestType::Md5 => 0,
            DigestType::Sha1 => 1,
        };
        (buf.len() - digest_len)..buf.len()
    });

    // encode avps
    let mut vector: Option<[u8; EncodeParams::RANDOM_VECTOR_LEN]> = None;
    let mut hidden_values: SmallVec<[(AttributeType, &[u8]); 12]> = SmallVec::new();
    for avp in avps {
        if !avp.hidden {
            avp.extend_to_vec(buf);
            continue;
        }
        let key = key.expect("missing key");
        let value = avp.value.as_ref();
        let vector = match vector.as_ref().and_then(|x| {
            hidden_values
                .iter()
                .all(|&(t, v)| t != avp.r#type || v == value)
                .then_some(x)
        }) {
            Some(x) => x,
            None => {
                vector = Some([0; EncodeParams::RANDOM_VECTOR_LEN]);
                let x = vector.as_mut().unwrap();
                rng.fill_bytes(x);
                (Avp {
                    vendor_id: VendorId::IETF,
                    r#type: AttributeType::RANDOM_VECTOR,
                    value: &*x,
                    mandatory: true,
                    hidden: false,
                })
                .extend_to_vec(buf);
                hidden_values.clear();
                x
            }
        };
        hidden_values.push((avp.r#type, value));
        let value_len = value.len().max(EncodeParams::padding_len(avp.r#type));
        let length = AVP_HEADER_LEN + 2 + value_len;
        if length > AVP_LENGTH_MASK as usize {
            panic!("AVP length exceeds maximum");
        }
        let mut hidden_value = Vec::with_capacity(value_len + 2);
        hidden_value.extend_from_slice(&(value.len() as u16).to_be_bytes());
        hidden_value.extend_from_slice(value);
        if hidden_value.len() < value_len + 2 {
            let padding = Range {
                start: hidden_value.len(),
                end: value_len + 2,
            };
            hidden_value.resize(value_len + 2, 0);
            rng.fill_bytes(&mut hidden_value[padding]);
        }
        hidden_value.resize(value_len + 2, 0);
        do_hide::<ENCRYPT>(&mut hidden_value, avp.r#type, key.hiding_key(), vector);
        (Avp {
            vendor_id: avp.vendor_id,
            r#type: avp.r#type,
            value: hidden_value.as_slice(),
            mandatory: avp.mandatory,
            hidden: true,
        })
        .extend_to_vec(buf);
    }

    // fill length
    if buf.len() > u16::MAX as usize {
        panic!("message length exceeds maximum");
    }
    *buf[LEN_RANGE].as_mut_array::<2>().unwrap() = (buf.len() as u16).to_be_bytes();

    // compute digest
    if let Some(digest_range) = digest_range {
        let key = key.unwrap();
        match EncodeParams::DIGEST_TYPE {
            // TODO: nonce
            DigestType::Md5 => {
                let tag = Hmac::<Md5>::new_from_slice(key.digest_key())
                    .unwrap()
                    .chain_update(local_nonce)
                    .chain_update(remote_nonce)
                    .chain_update(&buf)
                    .finalize()
                    .into_bytes();
                buf[digest_range].copy_from_slice(&tag);
            }
            DigestType::Sha1 => {
                let tag = Hmac::<Sha1>::new_from_slice(key.digest_key())
                    .unwrap()
                    .chain_update(local_nonce)
                    .chain_update(remote_nonce)
                    .chain_update(&buf)
                    .finalize()
                    .into_bytes();
                buf[digest_range].copy_from_slice(&tag);
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let key = Key::new(b"password");
        let msg = Message {
            header: Header {
                conn_id: 0x1234_5678,
                ns: 9,
                nr: 7,
            },
            body: Some((
                Avp {
                    vendor_id: VendorId::IETF,
                    r#type: AttributeType::MESSAGE_TYPE,
                    value: MessageType::HELLO,
                    mandatory: true,
                    hidden: false,
                },
                vec![Avp {
                    vendor_id: VendorId(1234),
                    r#type: AttributeType(456),
                    value: Cow::from(b"test host"),
                    mandatory: true,
                    hidden: true,
                }],
            )),
        };
        let mut buf = Vec::new();
        let nonce1 = b"abc";
        let nonce2 = b"def";
        encode_and_sign(&mut buf, &msg, Some(&key), nonce1, nonce2);
        println!("buf: {:?}", buf);
        let key2 = Key::new(b"password2");
        let keys = &[key2, key];
        let (decoded_msg, matched_key) = decode_and_verify(&buf, keys, nonce2, nonce1).unwrap();
        assert_eq!(decoded_msg, msg);
        assert_eq!(keys.element_offset(matched_key.unwrap()), Some(1));
    }
}
