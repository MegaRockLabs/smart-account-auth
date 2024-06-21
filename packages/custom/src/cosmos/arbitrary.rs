use core::fmt::Display;

#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
use saa_common::{hashes::sha256, AuthError, Binary, CredentialId, String, ToString, Verifiable};
use super::utils::{preamble_msg_arb_036, pubkey_to_account};
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct CosmosArbitrary<M: Display + Clone = String> {
    pub pubkey:    Binary,
    pub signature: Binary,
    pub message:   M,
    pub hrp:       Option<String>
}


impl<M: Display + Clone> Verifiable for CosmosArbitrary<M> {

    fn id(&self) -> CredentialId {
        self.pubkey.0.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.signature.len() > 0 &&
            self.message.to_string().len() > 0 && 
            self.pubkey.len() > 0) {
            return Err(AuthError::MissingData("Empty credential data".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        use saa_common::ensure;
        ensure!(self.hrp.is_some(), AuthError::Generic("Must provide prefix for native logic".to_string()));
        let addr  = pubkey_to_account(&self.pubkey, &self.hrp.as_ref().unwrap())?;
        let digest = sha256(&preamble_msg_arb_036(&addr, &self.message.to_string()).as_bytes());
        let res = saa_common::crypto::secp256k1_verify(
            &digest,
            &self.signature,
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }



    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(
        &self, 
        api:  &dyn Api, 
        _:  &Env,
        _:  &Option<MessageInfo>
    ) -> Result<Self, AuthError> {
        use super::utils::pubkey_to_canonical;
        let addr = match self.hrp.as_ref() {
            Some(hrp) => pubkey_to_account(&self.pubkey, hrp)?,
            None => api.addr_humanize(&pubkey_to_canonical(&self.pubkey))?.to_string()
        };
        let digest = sha256(&preamble_msg_arb_036(&addr, &self.message.to_string()).as_bytes());
        let res = api.secp256k1_verify(
            &digest,
            &self.signature,
            &self.pubkey
        )?;
        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }
        Ok(self.clone())
    }
}