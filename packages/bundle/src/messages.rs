#[cfg(feature = "session")]
pub(crate) mod impls;
#[cfg(feature = "session")]
pub mod actions;
#[cfg(feature = "session")]
pub mod sessions;
#[cfg(feature = "replay")]
pub mod replay;


#[saa_schema::saa_type]
pub enum SignedPayload {
    Credential(super::credential::Credential),
    Data(saa_common::types::msgs::SignedDataMsg),
}