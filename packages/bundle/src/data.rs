use saa_common::Vec;
use saa_schema::wasm_serde;
use crate::Credential;


/// CredentialData is wrapper for dealing with multiple credentials at the same time.
/// Implements both `Verifiable` and `CredentialWrapper` traits.
#[wasm_serde]
pub struct CredentialData {
    /// The list of credentials to be verified
    pub credentials            :  Vec<Credential>,
    /// A flag indicating that the environment can derive an additional credential
    /// that isn't included in the list of credentials directly.
    /// Most typically it's the transaction signer that has been verified beforehand
    /// but can be any other authorized dicated by the environment / smart contract logic
    pub use_native             :  Option<bool>,
    /// An optional index indicating which credential will be used as the primary. Default to the first one
    pub primary_index          :  Option<u8>,
}


#[wasm_serde]
pub enum UpdateOperation<A = CredentialData> {
    Add(A),
    Remove(A),
}


