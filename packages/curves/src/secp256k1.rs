use saa_common::{
    CredentialInfo, CredentialName,CredentialId,  
    AuthError, Binary, ToString, Verifiable,
    ensure, hashes::sha256
};

use saa_schema::wasm_serde;

#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env};




#[wasm_serde]
pub struct Secp256k1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
    pub hrp:       Option<String>
}



impl Verifiable for Secp256k1 {

    fn id(&self) -> CredentialId {
        self.pubkey.0.clone()
    }

    fn human_id(&self) -> String {
        self.pubkey.to_base64()
    }


    fn info(&self) -> CredentialInfo {
        CredentialInfo {
            name: CredentialName::Secp256k1,
            hrp: self.hrp.clone(),
            extension: None,
        }
    }

    fn message(&self) -> Binary {
        self.message.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.signature.len() > 0 &&
                self.message.len() > 0 && 
                self.pubkey.len() > 0,
            AuthError::MissingData("Empty credential data".to_string())
        );
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let res = saa_common::crypto::secp256k1_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api: &dyn Api, _: &Env) -> Result<(), AuthError> {
        let res = api.secp256k1_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }
}
