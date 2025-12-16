use deku::prelude::*;

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
    Reserved,
    #[deku(id = 1)]
    ENCR,
    #[deku(id = 2)]
    PRF,
    #[deku(id = 3)]
    INTEG,
    #[deku(id = 4)]
    KE,
    #[deku(id = 5)]
    SN,
    #[deku(id = 6)]
    ADDKE1,
    #[deku(id = 7)]
    ADDKE2,
    #[deku(id = 8)]
    ADDKE3,
    #[deku(id = 9)]
    ADDKE4,
    #[deku(id = 10)]
    ADDKE5,
    #[deku(id = 11)]
    ADDKE6,
    #[deku(id = 12)]
    ADDKE7,
    #[deku(id = 13)]
    KWA,
    #[deku(id = 14)]
    GCAUTH,
    #[deku(id_pat = "15..=240")]
    Unassigned(u8),
    #[deku(id_pat = "241..=255")]
    Private(u8),
}

/// Transform Type 1 - Encryption Algorithm Transform IDs
/// https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum ENCRTransformID {
    #[deku(id = 0)]
    Reserved0,
    #[deku(id = 1)]
    ENCR_DES_IV64,
    #[deku(id = 2)]
    ENCR_DES,
    #[deku(id = 3)]
    ENCR_3DES,
    #[deku(id = 4)]
    ENCR_RC5,
    #[deku(id = 5)]
    ENCR_IDEA,
    #[deku(id = 6)]
    ENCR_CAST,
    #[deku(id = 7)]
    ENCR_BLOWFISH,
    #[deku(id = 8)]
    ENCR_3IDEA,
    #[deku(id = 9)]
    ENCR_DES_IV32,
    #[deku(id = 10)]
    Reserved1,
    #[deku(id = 11)]
    ENCR_NULL,
    #[deku(id = 12)]
    ENCR_AES_CBC,
    #[deku(id = 13)]
    ENCR_AES_CTR,
    #[deku(id = 14)]
    ENCR_AES_CCM_8,
    #[deku(id = 15)]
    ENCR_AES_CCM_12,
    #[deku(id = 16)]
    ENCR_AES_CCM_16,
    #[deku(id = 17)]
    Unassigned0,
    #[deku(id = 18)]
    ENCR_AES_GCM_8,
    #[deku(id = 19)]
    ENCR_AES_GCM_12,
    #[deku(id = 20)]
    ENCR_AES_GCM_16,
    #[deku(id = 21)]
    ENCR_NULL_AUTH_AES_GMAC,
    #[deku(id = 22)]
    Reserved2,
    #[deku(id = 23)]
    ENCR_CAMELLIA_CBC,
    #[deku(id = 24)]
    ENCR_CAMELLIA_CTR,
    #[deku(id = 25)]
    ENCR_CAMELLIA_CCM_8,
    #[deku(id = 26)]
    ENCR_CAMELLIA_CCM_12,
    #[deku(id = 27)]
    ENCR_CAMELLIA_CCM_16,
    #[deku(id = 28)]
    ENCR_CHACHA20_POLY1305,
    #[deku(id = 29)]
    ENCR_AES_CCM_8_IIV,
    #[deku(id = 30)]
    ENCR_AES_GCM_16_IIV,
    #[deku(id = 31)]
    ENCR_CHACHA20_POLY1305_IIV,
    #[deku(id = 32)]
    ENCR_KUZNYECHIK_MGM_KTREE,
    #[deku(id = 33)]
    ENCR_MAGMA_MGM_KTREE,
    #[deku(id = 34)]
    ENCR_KUZNYECHIK_MGM_MAC_KTREE,
    #[deku(id = 35)]
    ENCR_MAGMA_MGM_MAC_KTREE,
    #[deku(id_pat = "36..=1023")]
    Unassigned1(u16),
    #[deku(id_pat = "1024..=65535")]
    Private(u16),
}

/// Transform Type 2 - Pseudorandom Function Transform IDs
/// https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-6
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum PRFTransformID {
    #[deku(id = 0)]
    Reserved,
    #[deku(id = 1)]
    PRF_HMAC_MD5,
    #[deku(id = 2)]
    PRF_HMAC_SHA1,
    #[deku(id = 3)]
    PRF_HMAC_TIGER,
    #[deku(id = 4)]
    PRF_AES128_XCBC,
    #[deku(id = 5)]
    PRF_HMAC_SHA2_256,
    #[deku(id = 6)]
    PRF_HMAC_SHA2_384,
    #[deku(id = 7)]
    PRF_HMAC_SHA2_512,
    #[deku(id = 8)]
    PRF_AES128_CMAC,
    #[deku(id = 9)]
    PRF_HMAC_STREEBOG_512,
    #[deku(id_pat = "10..=1023")]
    Unassigned(u16),
    #[deku(id_pat = "1024..=65535")]
    Private(u16),
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
