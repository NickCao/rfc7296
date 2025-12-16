use deku::prelude::*;

/// IKEv2 Exchange Types
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-1
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum ExchangeType {
    #[deku(id_pat = "0..=33")]
    Reserved(u8),
    #[deku(id = 34)]
    IKE_SA_INIT,
    #[deku(id = 35)]
    IKE_AUTH,
    #[deku(id = 36)]
    CREATE_CHILD_SA,
    #[deku(id = 37)]
    INFORMATIONAL,
    #[deku(id = 38)]
    IKE_SESSION_RESUME,
    #[deku(id = 39)]
    GSA_AUTH,
    #[deku(id = 40)]
    GSA_REGISTRATION,
    #[deku(id = 41)]
    GSA_REKEY,
    #[deku(id = 42)]
    GSA_INBAND_REKEY,
    #[deku(id = 43)]
    IKE_INTERMEDIATE,
    #[deku(id = 44)]
    IKE_FOLLOWUP_KE,
    #[deku(id_pat = "45..=239")]
    Unassigned(u8),
    #[deku(id_pat = "240..=255")]
    Private(u8),
}

/// IKEv2 Payload Types
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum PayloadType {
    #[deku(id = 0)]
    NoNextPayload,
    #[deku(id_pat = "1..=32")]
    Reserved(u8),
    #[deku(id = 33)]
    SA,
    #[deku(id = 34)]
    KE,
    #[deku(id = 35)]
    IDi,
    #[deku(id = 36)]
    IDr,
    #[deku(id = 37)]
    CERT,
    #[deku(id = 38)]
    CERTREQ,
    #[deku(id = 39)]
    AUTH,
    #[deku(id = 40)]
    Nonce,
    #[deku(id = 41)]
    N,
    #[deku(id = 42)]
    D,
    #[deku(id = 43)]
    V,
    #[deku(id = 44)]
    TSi,
    #[deku(id = 45)]
    TSr,
    #[deku(id = 46)]
    SK,
    #[deku(id = 47)]
    CP,
    #[deku(id = 48)]
    EAP,
    #[deku(id = 49)]
    GSPM,
    #[deku(id = 50)]
    IDg,
    #[deku(id = 51)]
    GSA,
    #[deku(id = 52)]
    KD,
    #[deku(id = 53)]
    SKF,
    #[deku(id = 54)]
    PS,
    #[deku(id_pat = "55..=127")]
    Unassigned(u8),
    #[deku(id_pat = "128..=255")]
    Private(u8),
}
