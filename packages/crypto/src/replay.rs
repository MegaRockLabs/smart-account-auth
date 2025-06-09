use saa_common::{ReplayError, Verifiable};


pub trait ReplayProtection : Verifiable {
    
    fn message_digest(&self) -> Vec<u8> {
        self.hash_message(self.message().as_ref())
    }


    fn hash_message(&self, bytes: &[u8]) -> Vec<u8> {
        crate::hashes::sha256(bytes).into()
    }


    #[cfg(feature = "cosmwasm")]
    fn check_replay<M: serde::Serialize>(
        &self,
        env: &saa_common::wasm::Env,
        messages: Vec<M>,
        nonce: u64,
    ) -> Result<(), ReplayError> {
        let data = saa_common::types::msgs::MsgDataToSign {
            chain_id: env.block.chain_id.clone(),
            contract_address: env.contract.address.to_string(),
            messages,
            nonce: nonce.into(),
        };
        let envelope_digest = self.hash_message(
            &saa_common::to_json_binary(&data)
                .map_err(|_| ReplayError::ToBin("MsgDataToSign".into()))?
        );
        saa_common::ensure!(envelope_digest == self.message_digest(), ReplayError::InvalidEnvelope);
        Ok(())
    }
    
}



/* #[cfg(feature = "cosmwasm")]
impl<V: saa_common::Verifiable> ReplayProtection for V  {
    
    fn check_replay<M: serde::Serialize>(
        &self,
        env: &saa_common::wasm::Env,
        messages: Vec<M>,
        nonce: u64,
    ) -> Result<(), ReplayError> {

        let data = saa_common::types::msgs::MsgDataToSign {
            chain_id: env.block.chain_id.clone(),
            contract_address: env.contract.address.to_string(),
            messages,
            nonce: nonce.into(),
        };

        let envelope_digest = self.hash_message(
            &saa_common::to_json_binary(&data)
                .map_err(|_| ReplayError::ToBin("MsgDataToSign".into()))?
        );

        saa_common::ensure!(envelope_digest == self.message_digest(), ReplayError::InvalidEnvelope);
        Ok(())
    }

}
 */