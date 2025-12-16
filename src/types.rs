use crate::consts::*;
use deku::prelude::*;

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct Header {
    initiator_spi: u64,
    responder_spi: u64,
    next_payload: u8,
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
#[deku(bit_order = "msb")]
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
