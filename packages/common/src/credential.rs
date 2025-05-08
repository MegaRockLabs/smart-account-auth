use saa_schema::wasm_serde;
use crate::{Binary, String};


pub type CredentialId = String;


#[wasm_serde]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: String,
    /// human readable prefix to encode from a public key
    pub hrp: Option<String>,
    /// extension data
    pub extension: Option<Binary>,
}




/* #[wasm_serde]
pub struct AccountCredentials {
    pub credentials: Vec<(CredentialId, CredentialInfo)>,
    pub verifying_id: CredentialId,
    pub native_caller: Option<CredentialId>,
}
 */


#[cfg(feature = "wasm")]
impl CredentialInfo {
    

    pub fn cosmos_address(&self, api: &dyn crate::wasm::Api, id: CredentialId) -> Result<crate::wasm::Addr, crate::AuthError> {
        use crate::utils::*;
        let name = self.name.clone();
        if name == "native" {
            let addr = api.addr_validate(&id)?;
            return Ok(addr)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == "eth_personal_sign" {
                return Ok(crate::wasm::Addr::unchecked(
                    pubkey_to_address(
                        id.as_bytes(), "inj"
                    )?
                ))
            } 
        }
        Ok(match &self.hrp {
            Some(hrp) => crate::wasm::Addr::unchecked(
                pubkey_to_address(id.as_bytes(), &hrp)?
            ),
            None => {
                let canon = pubkey_to_canonical(
                    id.as_bytes()
                );
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }
}