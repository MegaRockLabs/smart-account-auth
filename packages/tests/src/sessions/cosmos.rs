use std::{fmt::Display, str::FromStr};

use cosmwasm_schema::cw_serde;

use cw_storage_plus::Item;
use cosmwasm_std::{testing::{mock_dependencies, mock_env, mock_info}, CosmosMsg};
use saa_schema::with_session;
use serde::Serialize;
use smart_account_auth::{messages::{Action, ActionDerivation, ActionName, ActionToDerive, AllowedActions, Authority, SessionKey}, CredentialData};

use smart_account_auth::types::expiration::Expiration;


#[with_session]
#[cw_serde]
pub enum ExecuteMsg {

    Execute { 
        msgs: Vec<CosmosMsg> 
    },

    MintToken {
        minter: String,
        msg: Option<CosmosMsg>
    },

    TransferToken {
        collection: String,
        token_id: String,
        recipient: String,
    },

    UpdateAccountData {
        account_data: Option<CredentialData>,
    },

    Freeze {},

    Purge {},
}




/* #[cw_serde]
#[derive(Display, VariantNames, EnumString, EnumDiscriminants, EnumIter)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(strum(serialize_all = "snake_case"))]
#[strum_discriminants(derive(strum_macros::VariantArray))]
pub enum StrumExecuteMsg {

    #[strum(to_string = "execute: {{ msgs: Vec<CosmosMsg> }}")]
    Execute { 
        msgs: Vec<CosmosMsg> 
    },

    MintToken {
        minter: String,
        msg: Option<CosmosMsg>
    },

    #[strum(to_string = "{{ \"transfer_token\": {{ \"collection\": \"{collection}\" }} }}")]
    TransferToken {
        collection: String,
        token_id: String,
        recipient: String,
    },

    UpdateAccountData {
        account_data: Option<CredentialData>,
    },

    Freeze {},

    Purge {},
}


 */

#[cw_serde]
pub struct ExecuteSession<M : Serialize + Display + ActionName = ExecuteMsg> {
    pub owner: String,
    pub msg: M
}






pub static SESSION_KEYS : Item<SessionKey<ExecuteMsg>> = Item::new("saa_keys");






#[test]
fn simple_named_actions_session_flow() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;
    let env = mock_env();
    let alice = mock_info("alice", &[]);
    let bob = mock_info("bob", &[]);

    let actions = vec![
        Action::Named(String::from("mint_token")), 
        Action::Named(String::from("transfer_token"))
    ];

    let key = SessionKey {
        actions: AllowedActions::List(actions),
        expiration: Expiration::AtHeight(env.block.height + 100),
        granter: Authority::Address(alice.sender.to_string()),
        grantee: Authority::Address(bob.sender.to_string()),
    };

    SESSION_KEYS.save(storage, &key).unwrap();

    let execute_session: ExecuteSession = ExecuteSession {
        owner: alice.sender.to_string(),
        msg: ExecuteMsg::MintToken {
            minter: bob.sender.to_string(),
            msg: None
        }
    };

    let key = SESSION_KEYS.load(storage).unwrap();

    if key.expiration.is_expired(&env.block) {
        panic!("Session key expired");
    }

    let msg = Action::<ExecuteMsg>::from_str(&execute_session.msg.to_string()).unwrap();

    if let AllowedActions::List(actions) = &key.actions {
        if !actions.contains(&msg) {
            panic!("Action not allowed");
        }
    } else {
        panic!("Invalid actions");
    }

}





#[test]
fn derived_session_actions() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;
    let env = mock_env();
    let alice = mock_info("alice", &[]);
    let bob = mock_info("bob", &[]);

    let mut derived = Action::Derived(ActionToDerive { 
        action: ExecuteMsg::MintToken { minter: "minter".into(), msg: None }, 
        method: ActionDerivation::Name,
    });

    let actions = vec![
        derived.clone(),
        Action::Named(String::from("transfer_token"))
    ];

    let key = SessionKey {
        actions: AllowedActions::List(actions),
        expiration: Expiration::AtHeight(env.block.height + 100),
        granter: Authority::Address(alice.sender.to_string()),
        grantee: Authority::Address(bob.sender.to_string()),
    };

   
    let derived_string = derived.to_string();
    println!("Derived action: {}", derived.to_string());



    let execute_session: ExecuteSession = ExecuteSession {
        owner: alice.sender.to_string(),
        msg: ExecuteMsg::MintToken {
            minter: bob.sender.to_string(),
            msg: None
        }
    };


    let success = match key.actions {
        AllowedActions::All { } => true,
        AllowedActions::Current(_) => false,
        AllowedActions::List(ref actions) => {
            let mut found = false;
            for action in actions {
                match action {
                    Action::Named(name) => {
                        if name == &derived_string {
                            found = true;
                        }
                    }
                    Action::Derived(derived) => {
                        let same_rule_derive = derived.method.derive_message(&execute_session.msg);
                        println!("Derived action: {}", same_rule_derive.to_string());
                        if same_rule_derive == derived_string {
                            found = true;
                        }
                    }
                    _ => {}
                }
            }
            found
        }
    };
    
    assert!(success, "Action not allowed");

}