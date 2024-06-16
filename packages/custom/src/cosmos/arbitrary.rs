#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
use saa_common::{ensure, hashes::sha256, AuthError, Binary, CredentialId, String, ToString, Verifiable};
use saa_schema::wasm_serde;
use super::utils::{preamble_msg_arb_036, pubkey_to_account};


#[wasm_serde]
pub struct CosmosArbitrary {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
    pub hrp:       Option<String>
}


impl Verifiable for CosmosArbitrary {

    fn id(&self) -> CredentialId {
        self.pubkey.0.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.signature.len() > 0 &&
            self.message.len() > 0 && 
            self.pubkey.len() > 0) {
            return Err(AuthError::MissingData("Empty credential data".to_string()));
        }
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        ensure!(self.hrp.is_some(), AuthError::Generic("Must ether provide prefix of the chain or use the API".to_string()));

        let addr  = pubkey_to_account(&self.pubkey, &self.hrp.as_ref().unwrap())?;
        let data  = String::from_utf8(self.message.0.clone())?;
        let digest = sha256(&preamble_msg_arb_036(addr.as_str(), &data).as_bytes());

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
        _:  &MessageInfo
    ) -> Result<Self, AuthError> {
        use super::utils::pubkey_to_canonical;

        let addr = match self.hrp.as_ref() {
            Some(hrp) => pubkey_to_account(&self.pubkey, hrp)?,
            None => api.addr_humanize(&pubkey_to_canonical(&self.pubkey))?.to_string()
        };
        let data : String = cosmwasm_std::from_json(&self.message)?;
        let digest = sha256(&preamble_msg_arb_036(addr.as_str(), &data).as_bytes());

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