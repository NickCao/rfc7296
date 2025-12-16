use deku::prelude::*;

/// Transform Type 1 - Encryption Algorithm Transform IDs
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum ENCR {
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
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-6
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum PRF {
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

/// Transform Type 3 - Integrity Algorithm Transform IDs
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum AUTH {
    #[deku(id = 0)]
    NONE,
    #[deku(id = 1)]
    AUTH_HMAC_MD5_96,
    #[deku(id = 2)]
    AUTH_HMAC_SHA1_96,
    #[deku(id = 3)]
    AUTH_DES_MAC,
    #[deku(id = 4)]
    AUTH_KPDK_MD5,
    #[deku(id = 5)]
    AUTH_AES_XCBC_96,
    #[deku(id = 6)]
    AUTH_HMAC_MD5_128,
    #[deku(id = 7)]
    AUTH_HMAC_SHA1_160,
    #[deku(id = 8)]
    AUTH_AES_CMAC_96,
    #[deku(id = 9)]
    AUTH_AES_128_GMAC,
    #[deku(id = 10)]
    AUTH_AES_192_GMAC,
    #[deku(id = 11)]
    AUTH_AES_256_GMAC,
    #[deku(id = 12)]
    AUTH_HMAC_SHA2_256_128,
    #[deku(id = 13)]
    AUTH_HMAC_SHA2_384_192,
    #[deku(id = 14)]
    AUTH_HMAC_SHA2_512_256,
    #[deku(id_pat = "15..=1023")]
    Unassigned(u16),
    #[deku(id_pat = "1024..=65535")]
    Private(u16),
}

/// Transform Type 4 - Key Exchange Method Transform IDs
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-8
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum KE {
    #[deku(id = 0)]
    NONE,
    #[deku(id = 1)]
    MODP_768,
    #[deku(id = 2)]
    MODP_1024,
    #[deku(id_pat = "3..=4")]
    Reserved0(u16),
    #[deku(id = 5)]
    MODP_1536,
    #[deku(id_pat = "6..=13")]
    Unassigned0(u16),
    #[deku(id = 14)]
    MODP_2048,
    #[deku(id = 15)]
    MODP_3072,
    #[deku(id = 16)]
    MODP_4096,
    #[deku(id = 17)]
    MODP_6144,
    #[deku(id = 18)]
    MODP_8192,
    #[deku(id = 19)]
    ECP_256,
    #[deku(id = 20)]
    ECP_384,
    #[deku(id = 21)]
    ECP_512,
    #[deku(id = 22)]
    MODP_1024_PRIME_160,
    #[deku(id = 23)]
    MODP_2048_PRIME_224,
    #[deku(id = 24)]
    MODP_2048_PRIME_256,
    #[deku(id = 25)]
    ECP_192,
    #[deku(id = 26)]
    ECP_224,
    #[deku(id = 27)]
    brainpoolP224r1,
    #[deku(id = 28)]
    brainpoolP256r1,
    #[deku(id = 29)]
    brainpoolP384r1,
    #[deku(id = 30)]
    brainpoolP512r1,
    #[deku(id = 31)]
    Curve25519,
    #[deku(id = 32)]
    Curve448,
    #[deku(id = 33)]
    GOST3410_2012_256,
    #[deku(id = 34)]
    GOST3410_2012_512,
    #[deku(id = 35)]
    ML_KEM_512,
    #[deku(id = 36)]
    ML_KEM_768,
    #[deku(id = 37)]
    ML_KEM_1024,
    #[deku(id_pat = "38..=1023")]
    Unassigned1(u16),
    #[deku(id_pat = "1024..=65535")]
    Private(u16),
}
