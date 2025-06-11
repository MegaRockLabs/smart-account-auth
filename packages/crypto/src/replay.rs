use saa_common::{ReplayError, Verifiable};


pub trait ReplayProtection : Verifiable {
    
    fn message_digest(&self) -> Vec<u8> {
        self.hash_message(self.message().as_ref())
    }


    fn hash_message(&self, bytes: &[u8]) -> Vec<u8> {
        crate::hashes::sha256(bytes).into()
    }


    #[cfg(any(feature = "cosmwasm", feature = "native"))]
    fn check_replay<M: serde::Serialize + core::fmt::Display + Clone>(
        &self,
        #[cfg(feature = "cosmwasm")]
        env: &saa_common::wasm::Env, 
        messages: &Option<Vec<M>>,
        nonce: u64,
    ) -> Result<(), ReplayError> {
        use saa_common::{types::signed::{MsgDataToSign, MsgDataToVerify}, from_json, ensure};
        if self.name() == saa_common::CredentialName::Native {
            return Ok(());
        }
        match messages {
            Some(msgs) => {
                let envelope_digest = self.hash_message(
                    &MsgDataToSign::new_binary(env, msgs.clone(), nonce)?
                );
                ensure!(envelope_digest == self.message_digest(), ReplayError::InvalidEnvelope);
            },
            None => {
                #[cfg(not(feature = "cosmwasm"))]
                return Err(ReplayError::MissingData("Messages".into()));
                let data : MsgDataToVerify = from_json(&self.message())
                    .map_err(|_| ReplayError::FromBin("MsgDataToVerify".into()))?;
                data.validate(env, nonce)?;
            }
        }
        Ok(())
    }
    
}


// implement for all &Credential whose enum value is Verifiable
impl<T> ReplayProtection for T  where T: Verifiable + std::ops::Deref<Target = dyn Verifiable> {}