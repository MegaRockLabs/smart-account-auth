
use saa_common::{to_json_binary, Binary, CredentialId};
use super::Session;
use crate::messages::actions::{DerivableMsg, Action};





impl Session {
    pub fn key(&self) -> CredentialId {
        let (id, info) = &self.grantee;
        let actions = to_json_binary(&self.actions).unwrap_or_default();

        let msg = [
            self.granter.as_bytes(),
            id.as_bytes(),
            info.name.to_string().as_bytes(),
            actions.as_slice(),
        ].concat();

        Binary::from(saa_common::hashes::sha256(&msg)).to_base64()
    }

     pub fn can_do_action(&self, act: &Action) -> bool {
        self.actions.can_do_action(act)
    }
    
    pub fn can_do_msg<M : DerivableMsg>(&self, message: &M) -> bool {
        self.actions.can_do_msg(message)
    }
    
}




