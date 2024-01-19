use saa_common::{AuthError, CredentialId, Verifiable};
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Caller {
    pub id: CredentialId
}


impl Verifiable for Caller {

    fn id(&self) -> CredentialId {
        self.id.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.id.len() > 0) {
            return Err(AuthError::InvalidLength("Caller must have an id".to_string()));
        }
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn cosmwasm_std::Api, _: &cosmwasm_std::Env) -> Result<(), AuthError> {
        let addr : String = cosmwasm_std::from_json(&self.id)?;
        api.addr_validate(&addr)?;
        Ok(())
    }
}