use std::ops::Deref;
use saa_common::{Verifiable, String};

#[cfg(any(feature = "cosmwasm", feature = "native"))]
use saa_common::{
    ReplayError, MsgDataToSign, CredentialName,
    to_json_binary as to_bin
};


#[derive(Clone, Debug)]
pub enum CheckOption {
    Messages(Vec<String>),
    Text(String),
    Nothing

}

#[derive(Clone, Debug)]
pub struct ReplayParams {
    pub override_id       :  Option<String>,
    pub override_address  :  Option<String>,
    pub checking          :  CheckOption,
    pub has_inners        :  bool,
    pub nonce             :  u64,
}



impl ReplayParams {
    pub fn new(
        nonce: u64,
        opt: CheckOption,
    ) -> Self {
        if let CheckOption::Nothing = opt {
            Self {
                override_id: None,
                override_address: None,
                checking: opt,
                has_inners: false,
                nonce,
            }
        } else {
            Self {
                override_id: None,
                override_address: None,
                checking: opt,
                has_inners: true,
                nonce,
            }
        }
    }
}



pub trait ReplayProtection : Verifiable {
    
    fn message_digest(&self) -> Vec<u8> {
        self.hash_message(self.message().as_ref())
    }


    fn hash_message(&self, bytes: &[u8]) -> Vec<u8> {
        crate::hashes::sha256(bytes).into()
    }


    #[cfg(any(feature = "cosmwasm", feature = "native"))]
    fn protect_reply(
        &self,
        #[cfg(feature = "cosmwasm")]
        env: &saa_common::wasm::Env, 
        params: ReplayParams,
    ) -> Result<(), ReplayError> {
        if self.name() == CredentialName::Native { return Ok(()) };
        let chain_id = match params.override_id {
            Some(ref id) => id.clone(),
            None => {
                #[cfg(not(feature = "cosmwasm"))]
                return Err(ReplayError::MissingData("Chain ID".into()));
                #[cfg(feature = "cosmwasm")]
                env.block.chain_id.clone()
            }
        };
        let addr = match params.override_address {
            Some(ref addr) => addr.clone(),
            None => {
                #[cfg(not(feature = "cosmwasm"))]
                return Err(ReplayError::MissingData("Contract Address".into()));
                #[cfg(feature = "cosmwasm")]
                env.contract.address.to_string()
            }
        };
        let msgs = match params.checking {
            CheckOption::Messages(msgs) => msgs,
            CheckOption::Text(t) => vec![t],
            CheckOption::Nothing => vec![],
        };

        let bin = to_bin(&MsgDataToSign::new(chain_id,addr,msgs,params.nonce))
            .map_err(|_| ReplayError::ToBin("MsgDataToSign".into()))?;

        if self.hash_message(&bin) != self.message_digest() {
            return Err(ReplayError::InvalidEnvelope(
                bin.to_string(), saa_common::Binary::from(self.message().to_vec()).to_string()
            ));
        }
        Ok(())
    }
    
}



// implement for all &Credential whose enum value is ReplayProtection
impl<T> ReplayProtection for T  
    where T: Deref<Target : ReplayProtection> + Verifiable 
{

    fn hash_message(&self, bytes: &[u8]) -> Vec<u8> {
        self.deref().hash_message(bytes)
    }

    fn message_digest(&self) -> Vec<u8> {
        self.deref().message_digest()
    }

    #[cfg(any(feature = "cosmwasm", feature = "native"))]
    fn protect_reply(
        &self,
        #[cfg(feature = "cosmwasm")]
        env: &saa_common::wasm::Env, 
        params: ReplayParams,
    ) -> Result<(), saa_common::ReplayError> {
        self.deref().protect_reply(
            #[cfg(feature = "cosmwasm")]
            env,
            params,
        )
    }

}
