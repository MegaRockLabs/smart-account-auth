
use core::fmt::Debug;
use saa_schema::wasm_serde;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{ensure, AuthError, Binary, CredentialId, CredentialName};


#[wasm_serde]
pub struct AuthPayload<E : Serialize = Binary> {
    pub hrp: Option<String>,
    pub address: Option<String>,
    pub credential_id: Option<CredentialId>,
    pub extension: Option<E>
}


impl<E : Serialize> AuthPayload<E> {

    fn validate(&self) -> Result<(), AuthError> {
        let error : &str = "Only one of the 'address' or 'hrp' can be provided";

        if self.hrp.is_some() {
            ensure!(
                self.address.is_none(),
                AuthError::generic(error)
            );
        }
        if self.address.is_some() {
            ensure!(self.hrp.is_none(), AuthError::generic(error));
            let addr = self.address.clone().unwrap();
            ensure!(addr.len() > 3 && addr.contains("1") , AuthError::generic("Invalid address"));
        }
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    pub fn validate_cosmwasm(
        &self, 
        storage: &dyn cosmwasm_std::Storage
    ) -> Result<(), AuthError> {
        use crate::CredentialName;

        self.validate()?;

        #[cfg(feature = "storage")]
        if self.credential_id.is_some() {

            let info_res = crate::storage::CREDENTIAL_INFOS.load(
                storage, self.credential_id.clone().unwrap()
            );
    
            ensure!(info_res.is_ok(), AuthError::generic("Credential not found"));
    
            if self.hrp.is_some() {
                let name = info_res.unwrap().name;
                ensure!(
                    name == CredentialName::CosmosArbitrary || name == CredentialName::Secp256k1,
                    AuthError::generic("'hrp' can only be passed for 'cosmos-arbitrary' or 'secp256k1'")
                );
            }
        }
        Ok(())
    }
    
}


#[wasm_serde]
pub struct IndexedAuthPayload<E : Serialize = Binary> {
    pub payload: AuthPayload<E>,
    pub index: u8,
}

impl<E : Serialize> IndexedAuthPayload<E> {
    pub fn validate(&self) -> Result<(), AuthError> {
        self.payload.validate()
    }

    #[cfg(feature = "cosmwasm")]
    pub fn validate_cosmwasm(&self, storage: &dyn cosmwasm_std::Storage) -> Result<(), AuthError> {
        self.payload.validate_cosmwasm(storage)
    }
}



#[wasm_serde]
pub struct MsgDataToSign<M: JsonSchema> {
    pub chain_id: String,
    pub contract_address: String,
    pub messages: Vec<M>,
    pub nonce: String,
}


#[wasm_serde]
pub struct SignedData<M : JsonSchema> {
    pub data: MsgDataToSign<M>,
    pub payload: Option<AuthPayload>,
    pub signature: Binary,
}




#[wasm_serde]
pub struct CredentialFullInfo<E : Serialize + Clone = Binary> {
    pub id: CredentialId,
    pub human_id: String,
    pub name: CredentialName,
    pub hrp: Option<String>,
    pub extension: Option<E>,
}


#[wasm_serde]
pub struct AccountCredentials<E : Serialize + Clone = Binary> {
    pub credentials: Vec<CredentialFullInfo<E>>,
    pub verifying_id: CredentialId,
    pub verifying_human_id: String,
    pub native_caller: bool,
}



#[cfg(feature = "cosmwasm")]
impl<A> cosmwasm_std::CustomMsg for SignedData<A> 
    where A : JsonSchema + Debug + Clone + PartialEq + Serialize
{}