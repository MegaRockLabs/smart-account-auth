#[cfg(feature = "session")]
pub(crate) mod impls;
#[cfg(feature = "session")]
pub mod actions;
#[cfg(feature = "session")]
pub mod sessions;


#[saa_schema::saa_type]
pub enum SignedPayload {
    Credential(super::credential::Credential),
    Data(saa_common::types::signed::SignedDataMsg),
}