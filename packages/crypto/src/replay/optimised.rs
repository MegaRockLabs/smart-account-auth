use saa_common::{Verifiable, String};
#[cfg(any(feature = "cosmwasm", feature = "native"))]
use saa_common::{
    ensure, ReplayError, MsgDataToSign, CredentialName,
    to_json_binary as to_bin
};

#[derive(Clone)]
pub enum CheckOption {
    Messages(Vec<String>),
    Text(String),
    Nothing

}

#[derive(Clone)]
pub struct ReplayParams {
    pub override_id       :  Option<String>,
    pub override_address  :  Option<String>,
    pub check_inner       :  CheckOption,
    pub has_inners        :  bool,
    pub nonce             :  u64,
}



impl ReplayParams {
    pub fn new(
        nonce: u64,
        to_check: CheckOption,
    ) -> Self {
        if let CheckOption::Nothing = to_check {
            Self {
                override_id: None,
                override_address: None,
                check_inner: to_check,
                has_inners: false,
                nonce,
            }
        } else {
            Self {
                override_id: None,
                override_address: None,
                check_inner: to_check,
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
        let msgs = match params.check_inner {
            CheckOption::Messages(msgs) => msgs,
            CheckOption::Text(t) => vec![t],
            CheckOption::Nothing => vec![],
        };
        let bin = to_bin(&MsgDataToSign::new(chain_id,addr,msgs,params.nonce))
                            .map_err(|_| ReplayError::ToBin("MsgDataToVerify".to_string()))?;
        ensure!(self.hash_message(&bin) == self.message_digest(), ReplayError::InvalidEnvelope);
        Ok(())
    }
    
}

