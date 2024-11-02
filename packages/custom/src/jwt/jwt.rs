#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
use saa_curves::secp256r1::secp256r1_verify;
use saa_schema::wasm_serde;

use saa_common::{
    hashes::sha256, AuthError, Binary, CredentialId, String, Verifiable, ensure
};

use sha2::{Digest, Sha256};



#[wasm_serde]
pub struct JWTCredential {
    /* TODO */
}


impl Verifiable for JWTCredential {

    fn id(&self) -> CredentialId {
        self.id.as_bytes().to_vec()
    }

    fn human_id(&self) -> String {
        self.id.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        todo!();
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, _: &dyn Api, _: &Env) -> Result<Self, AuthError> {
        todo!();
    }
}

