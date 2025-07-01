use saa_common::{ReplayError, Verifiable, String};
#[cfg(any(feature = "cosmwasm", feature = "native"))]
use saa_common::{ensure, MsgDataToSign, to_json_binary as to_bin};


#[derive(Debug, Clone)]
pub enum CheckOption<M: serde::Serialize + core::fmt::Display = String> {
    Messages(Vec<M>),
    Text(String),
    Nothing
}

#[derive(Debug, Clone)]
pub struct ReplayParams<M: serde::Serialize + core::fmt::Display = String> {
    pub override_id       :  Option<String>,
    pub override_address  :  Option<String>,
    pub checking          :  CheckOption<M>,
    pub has_inners        :  bool,
    pub nonce             :  u64,
}



impl<M : serde::Serialize + core::fmt::Display> ReplayParams<M> {
    pub fn new(
        nonce: u64,
        opt: CheckOption<M>,
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
    fn protect_reply<M: serde::Serialize + core::fmt::Display + Clone>(
        &self,
        #[cfg(feature = "cosmwasm")]
        env: &saa_common::wasm::Env, 
        params: ReplayParams<M>,
    ) -> Result<(), saa_common::ReplayError> {
        use saa_common::Binary;
        use ReplayError::InvalidEnvelope;

        if self.name() == saa_common::CredentialName::Native {
            return Ok(());
        }
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
        let option = params.checking;
        let nonce = params.nonce;
        if let CheckOption::Nothing = option {
            let data : saa_common::MsgDataToVerify = saa_common::from_json(&self.message())
                    .map_err(|_| ReplayError::FromBin("MsgDataToVerify".into()))?;
            ensure!(data.chain_id == chain_id, ReplayError::ChainIdMismatch);
            ensure!(data.contract_address == addr, ReplayError::AddressMismatch);
            ensure!(data.nonce.u64() == nonce, ReplayError::InvalidNonce(nonce));
            return Ok(());
        }
        let bin = if let CheckOption::Messages(msgs) = option {
             to_bin(&MsgDataToSign::new(chain_id,addr,msgs,nonce))
            .map_err(|_| ReplayError::ToBin("MsgDataToVerify".to_string()))?
        } else {
            let strs = if let CheckOption::Text(t) = option { vec![t] } else { vec![] };
            to_bin(&MsgDataToSign::new(chain_id,addr,strs,nonce))
            .map_err(|_| ReplayError::ToBin("MsgDataToVerify".to_string()))?
        };

        let equal = self.hash_message(&bin) == self.message_digest();
        ensure!(equal, InvalidEnvelope(bin.to_string(), Binary::from(self.message().to_vec()).to_string()));
        Ok(())
    }
    
}

