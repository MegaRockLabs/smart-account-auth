#[cfg(feature = "replay")]
use saa_common::Uint64;
use saa_common::{wasm::Addr, CredentialId, CredentialRecord};
use saa_schema::saa_type;


/// CredentialData is wrapper for dealing with multiple credentials at the same time.
/// Implements both `Verifiable` and `CredentialWrapper` traits.
#[saa_type]
pub struct CredentialData {
    /// The list of credentials to be verified
    pub credentials            :  Vec<crate::Credential>,
    /// A flag indicating that the environment can derive an additional credential
    /// that isn't included in the list of credentials directly.
    /// Most typically it's the transaction signer that has been verified beforehand
    /// but can be any other authorized dicated by the environment / smart contract logic
    pub use_native             :  Option<bool>,
    /// An optional index indicating which credential will be used as the primary. Default to the first one
    pub primary_index          :  Option<usize>,
    /// An optional flag that tell us whether to perform an extensive validation before verifying each one thouroughly
    pub pre_validate           :  Option<bool>,
    /// An optional flag that indicates whether that 
    pub override_primary       :  Option<bool>,
    /// A custom nonce value to use for replay attack protection. Meant to be set by verifier, not user. 0 by default.
    #[cfg(feature = "replay")]
    pub nonce                  :   Option<Uint64>,
}





#[saa_type]
pub struct VerifiedData {
    /// a list of verified credentials that have passed all checks
    pub credentials         :    Vec<CredentialRecord>,
    /// a list of addresses (recognized by the environment) were derived from the credentials
    pub addresses           :    Vec<Addr>,

    /// an id of a credential that is considered primary in the batch
    pub verifying_id        :    CredentialId,
    /// in case if we updating an existing state with new credentials, this flag indicates
    /// whether to override the existing primary credential with the primary from this batch
    pub override_ver        :    bool,

    /// a flag indicating that the batch has credentials native to the environment like `caller` or `info.sender``
    pub has_natives         :    bool,
    /// a flag indicating that there is at least one credential wuth addutional properties to be reused e.g. `Passkeys``
    pub has_extensions      :    bool,

    #[cfg(feature = "replay")]
    /// a nonce value used for replay attack protection
    pub nonce           :    u64
}