use deku::prelude::*;

/// IKEv2 Exchange Types
/// Reference: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-1
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
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
