use deku::prelude::*;

use crate::transform;

/// IKEv2 Exchange Types
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-1
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
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
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
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

/// IKEv2 Security Protocol Identifiers
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-18
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum ProtocolIdentifier {
    #[deku(id = 0)]
    Reserved,
    #[deku(id = 1)]
    IKE,
    #[deku(id = 2)]
    AH,
    #[deku(id = 3)]
    ESP,
    #[deku(id = 4)]
    FC_ESP_HEADER,
    #[deku(id = 5)]
    FC_CT_AUTHENTICATION,
    #[deku(id = 6)]
    GIKE_UPDATE,
    #[deku(id_pat = "7..=200")]
    Unassigned(u8),
    #[deku(id_pat = "201..=255")]
    Private(u8),
}

/// Transform Type Values
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-3
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum TransformType {
    #[deku(id = 0)]
    Reserved(u8, u16),
    #[deku(id = 1)]
    ENCR(u8, transform::ENCR),
    #[deku(id = 2)]
    PRF(u8, transform::PRF),
    #[deku(id = 3)]
    INTEG(u8, u16),
    #[deku(id = 4)]
    KE(u8, transform::KE),
    #[deku(id = 5)]
    SN(u8, transform::SN),
    #[deku(id = 6)]
    ADDKE1(u8, u16),
    #[deku(id = 7)]
    ADDKE2(u8, u16),
    #[deku(id = 8)]
    ADDKE3(u8, u16),
    #[deku(id = 9)]
    ADDKE4(u8, u16),
    #[deku(id = 10)]
    ADDKE5(u8, u16),
    #[deku(id = 11)]
    ADDKE6(u8, u16),
    #[deku(id = 12)]
    ADDKE7(u8, u16),
    #[deku(id = 13)]
    KWA(u8, transform::KWA),
    #[deku(id = 14)]
    GCAUTH(u8, u16),
    #[deku(id_pat = "15..=240")]
    Unassigned(u8, u8, u16),
    #[deku(id_pat = "241..=255")]
    Private(u8, u8, u16),
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum LastSubstructure {
    #[deku(id = 0)]
    Last,
    #[deku(id = 2)]
    Proposal,
    #[deku(id = 3)]
    Transform,
}
