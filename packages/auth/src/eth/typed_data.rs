
#[cfg(any(feature = "cosmwasm", feature = "native"))]
use {super::utils::{get_recovery_param, preamble_msg_eth}, saa_common::ensure};
use saa_common::{AuthError, Binary, CredentialId, String, ToString, Uint64, Verifiable };
use saa_schema::saa_type;

// TODO: remove (crate) restrictions once ready



/// Taken from [ethers-rs](https://github.com/gakonst/ethers-rs/blob/6e2ff0ef8af8c0ee3c21b7e1960f8c025bcd5588/ethers-core/src/types/transaction/eip712.rs#L107)
/// Eip712 Domain attributes used in determining the domain separator;
/// Unused fields are left out of the struct type.
///
/// Protocol designers only need to include the fields that make sense for their signing domain.
/// Unused fields are left out of the struct type.
#[saa_type]
pub struct EIP712Domain {
    ///  The user readable name of signing domain, i.e. the name of the DApp or the protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The current major version of the signing domain. Signatures from different versions are not
    /// compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The EIP-155 chain id. The user-agent should refuse signing if it does not match the
    /// currently active chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<Uint64>,

    /// The address of the contract that will verify the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,

    /// A disambiguating salt for the protocol. This can be used as a domain separator of last
    /// resort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<Binary>,
}


// at the moment is a dummy copy of personal sign
#[saa_type]
pub(crate) struct EthTypedData{
    pub message:   Binary,
    pub signature: Binary,
    pub signer:    String,
}



impl Verifiable for EthTypedData {

    fn id(&self) -> CredentialId {
        self.signer.to_string()
    }


    fn validate(&self) -> Result<(), AuthError> {
        if !self.signer.starts_with("0x") {
            return Err(AuthError::MissingData("Ethereum `signer` address must start with 0x".to_string()));
        }
        if self.signature.len() < 65 {
            return Err(AuthError::MissingData("Signature must be at least 65 bytes".to_string()));
        }
        let signer_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;

        if signer_bytes.len() != 20 {
            return Err(AuthError::MissingData("Signer must be 20 bytes".to_string()));
        }
        Ok(())
    }


    #[cfg(feature = "native")] 
    fn verify(&self) -> Result<(), AuthError> {
        let signature = &self.signature.to_vec();
        let key_data = saa_crypto::secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
        let hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
        .map_err(|e| AuthError::generic(e.to_string()))?;
    
        ensure!(addr_bytes == hash[12..], AuthError::RecoveryMismatch);
        
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api: &dyn saa_common::wasm::Api) -> Result<(), AuthError> {
        
        let signature = &self.signature.to_vec();
        
        let key_data = api.secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
    
        let hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;
        
        ensure!(addr_bytes == hash[12..], AuthError::RecoveryMismatch);

        Ok(())
    }


}

