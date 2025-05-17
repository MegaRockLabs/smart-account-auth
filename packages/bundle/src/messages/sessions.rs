use saa_schema::saa_type;
use saa_common::{Binary, CredentialId, Expiration, Vec, String, vec, hashes::sha256};
use crate::{credential::CredentialRecord, msgs::{Action, AllowedActions, DerivableMsg}};


type GranteeInfo = CredentialRecord;


#[saa_type]
pub struct SessionInfo  {
    pub grantee     :       GranteeInfo,
    pub granter     :       Option<CredentialId>,
    pub expiration  :       Option<Expiration>,
}



#[saa_type]
pub struct Session {
    pub granter     : CredentialId,
    pub grantee     : GranteeInfo,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration,
    #[cfg(feature = "replay")]
    pub nonce       : u64,
}




impl Session {

    pub fn key(&self) -> CredentialId {
        let (id, info) = &self.grantee;
        
        let actions  = match self.actions {
            AllowedActions::All {  } => vec![],
            AllowedActions::Include(ref actions) => {
                actions.iter().map(|a| a.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
                    .as_bytes()
                    .to_vec()
            }
        };

        Binary::from(
            sha256(
            &[
                    self.granter.as_bytes(),
                    id.as_bytes(),
                    info.name.to_string().as_bytes(),
                    actions.as_slice()
                ]
                .concat()
            )
        ).to_base64()
    }

    pub fn can_do_action(&self, act: &Action) -> bool {
        self.actions.can_do_action(act)
    }
    
    pub fn can_do_msg<M : DerivableMsg>(&self, message: &M) -> bool {
        self.actions.can_do_msg(message)
    }
}


