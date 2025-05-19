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
    pub primary_index          :  Option<u8>,
}
