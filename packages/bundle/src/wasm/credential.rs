use crate::{credential::CredentialName, Credential};
use saa_common::{wasm::{Addr, Api}, AuthError};

#[cfg(feature = "storage")]
use saa_common::{
    wasm::{
        Storage, Env, MessageInfo,
        storage::{has_credential, save_credential, increment_account_number}
    }, 
    stores::CALLER,
    from_json,
    Verifiable, 
    ensure
};



impl Credential {

    pub fn is_cosmos_derivable(&self) -> bool {
        self.hrp().is_some()
    }

    pub fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        let name = self.name();
        if name == CredentialName::Caller {
            let address =  String::from_utf8(self.id())
                                .map(|s| Addr::unchecked(s))?;
            return Ok(address)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    saa_common::utils::pubkey_to_address(
                        &self.id(), "inj"
                    )?
                ))
            } 
        }
        Ok(match self.hrp() {
            Some(hrp) => Addr::unchecked(
                saa_common::utils::pubkey_to_address(&self.id(), &hrp)?
            ),
            None => {
                let canon = saa_common::utils::pubkey_to_canonical(&self.id());
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }


    #[cfg(feature = "storage")]
    pub fn assert_cosmwasm(
        &self, 
        api     :  &dyn Api, 
        storage :  &dyn Storage,
        env     :  &Env, 
    ) -> Result<(), AuthError> {
        ensure!(has_credential(storage, &self.id()), AuthError::NotFound);
        self.verify_cosmwasm(api)?;
        #[cfg(feature = "replay")]
        {
            let msg : saa_common::messages::MsgDataToVerify = from_json(&self.message())?;
            msg.validate_cosmwasm(storage, env)?;
        }
        Ok(())
    }

    
    #[cfg(feature = "storage")]
    pub fn save_cosmwasm(&self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env:  &Env,
        info: &MessageInfo
    ) -> Result<(), AuthError> {
        self.assert_cosmwasm(api, storage, env)?;
        save_credential(storage, &self.id(), &self.info())?;
        #[cfg(feature = "replay")]
        increment_account_number(storage)?;
        if let Credential::Caller(_) = self {
            CALLER.save(storage, &Some(info.sender.to_string()))?;
        }
        Ok(())
    }
}