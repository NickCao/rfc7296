use std::num::NonZeroU64;

use crate::consts::*;
use deku::prelude::*;

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct IKEHeader {
    initiator_spi: NonZeroU64,
    responder_spi: u64,
    next_payload: PayloadType,
    #[deku(bits = 4)]
    major_version: u8,
    #[deku(bits = 4)]
    minor_version: u8,
    exchange_type: ExchangeType,
    flags: Flags,
    message_id: u32,
    length: u32,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct PayloadHeader {
    next_payload: PayloadType,
    #[deku(bits = 1)]
    critical: bool,
    #[deku(bits = 7)]
    reserved: u8,
    payload_length: u16,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct Flags {
    #[deku(bits = 1)]
    unused_0: bool,
    #[deku(bits = 1)]
    unused_1: bool,
    #[deku(bits = 1)]
    response: bool,
    #[deku(bits = 1)]
    version: bool,
    #[deku(bits = 1)]
    initiator: bool,
    #[deku(bits = 1)]
    unused_2: bool,
    #[deku(bits = 1)]
    unused_3: bool,
    #[deku(bits = 1)]
    unused_4: bool,
}

#[cfg(test)]
mod test {
    use std::num::NonZero;

    use super::*;

    #[test]
    fn test_header() {
        let header: &[u8] = &[
            0x62, 0xb5, 0x6d, 0x9c, 0x3a, 0x55, 0x9d, 0x62, 0xe8, 0x34, 0x54, 0x2c, 0x8, 0xab,
            0xba, 0x1a, 0x2e, 0x20, 0x25, 0x8, 0x0, 0x0, 0x1, 0xb9, 0x0, 0x0, 0x0, 0x50, 0x0, 0x0,
            0x0, 0x34, 0x94, 0xf0, 0x7b, 0x30, 0x4e, 0x49, 0x9e, 0x51, 0x77, 0x15, 0xf8, 0x77,
            0x31, 0xfd, 0xa4, 0xe7, 0x58, 0x7f, 0x82, 0x4e, 0x94, 0x70, 0x96, 0x6f, 0xa4, 0x1,
            0x68, 0xb6, 0x1b, 0x9e, 0xcb, 0x36, 0x7a, 0x19, 0xf6, 0xfc, 0x84, 0xc5, 0x51, 0xde,
            0x3a, 0x58, 0x38, 0x8f, 0xac, 0x94, 0xf1, 0xdd,
        ];
        assert_eq!(
            IKEHeader::try_from(&header[..28]),
            Ok(IKEHeader {
                initiator_spi: NonZero::new(0x62b56d9c3a559d62).unwrap(),
                responder_spi: 0xe834542c08abba1a,
                next_payload: PayloadType::SK,
                major_version: 2,
                minor_version: 0,
                exchange_type: ExchangeType::INFORMATIONAL,
                flags: Flags {
                    unused_0: false,
                    unused_1: false,
                    response: false,
                    version: false,
                    initiator: true,
                    unused_2: false,
                    unused_3: false,
                    unused_4: false,
                },
                message_id: 0x000001b9,
                length: 80,
            })
        );
    }
}
