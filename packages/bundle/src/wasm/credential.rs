use crate::{credential::CredentialName, Credential};
use saa_common::{wasm::{Addr, Api}, AuthError};


impl Credential {

    pub fn is_cosmos_derivable(&self) -> bool {
        self.hrp().is_some()
    }

    pub fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        use saa_common::utils::*;
        let name = self.name();
        if name == CredentialName::Native {
            let addr = api.addr_validate(&self.id())?;
            return Ok(addr)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    pubkey_to_address(
                        &self.id().as_bytes(), "inj"
                    )?
                ))
            } 
        }
        Ok(match self.hrp() {
            Some(hrp) => Addr::unchecked(
                pubkey_to_address(self.id().as_bytes(), &hrp)?
            ),
            None => {
                let canon = pubkey_to_canonical(
                    self.id().as_bytes()
                );
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }


}