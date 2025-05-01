use std::fmt::Display;
use cosmwasm_schema::cw_serde;
use cw_storage_plus::Item;
use cosmwasm_std::{testing::{mock_dependencies, mock_env, mock_info}, BankMsg, CosmosMsg};
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

    #[strum(to_string = "{{ \"mint_token\": {{ \"minter\": \"{minter}\" }} }}")]
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


    assert!(key.actions.is_allowed(&execute_session.msg));


}





#[test]
fn derived_session_actions() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let _storage = deps.storage;
    let env = mock_env();
    let alice = mock_info("alice", &[]);
    let bob = mock_info("bob", &[]);


    let actions = vec![
        Action::Derived(ActionToDerive { 
            action: ExecuteMsg::MintToken { minter: "minter".into(), msg: None }, 
            method: ActionDerivation::Name,
        }),
        Action::Named(String::from("transfer_token"))
    ];

    let key = SessionKey {
        actions: AllowedActions::List(actions),
        expiration: Expiration::AtHeight(env.block.height + 100),
        granter: Authority::Address(alice.sender.to_string()),
        grantee: Authority::Address(bob.sender.to_string()),
    };

   

    // Ok
    assert!(key.actions.is_allowed(&ExecuteMsg::MintToken {
        minter: bob.sender.to_string(),
        msg: None
    }));

    // Ok
    assert!(key.actions.is_allowed(&ExecuteMsg::TransferToken { 
        collection: String::from("collection"),
        token_id: String::from("token_id"),
        recipient: String::from("recipient"),
    }));


    // Not Ok
    assert!(!key.actions.is_allowed(&ExecuteMsg::Freeze {  }));
    assert!(!key.actions.is_allowed(&ExecuteMsg::Execute { msgs: vec![] }));

}






#[test]
fn advanced_action_derivations() {
    let env = mock_env();

    let alice = mock_info("alice", &[]);
    let bob = mock_info("bob", &[]);


    let actions = vec![
   
        Action::Derived(ActionToDerive { 
            action: ExecuteMsg::MintToken { minter: "minter".into(), msg: None }, 
            method: ActionDerivation::String,
        }),
        Action::Derived(ActionToDerive { 
            action: ExecuteMsg::MintToken { minter: "Gimmy".into(), msg: None }, 
            method: ActionDerivation::String,
        }),
        Action::Derived(ActionToDerive { 
            action: ExecuteMsg::MintToken { 
                minter: "sensei".into(), 
                msg: Some(CosmosMsg::Bank(BankMsg::Send {
                    to_address: String::from("to_address"),
                    amount: vec![],
                })), 
            },
            method: ActionDerivation::Json,
        }),
    ];

    let key = SessionKey {
        actions: AllowedActions::List(actions.clone()),
        expiration: Expiration::AtHeight(env.block.height + 100),
        granter: Authority::Address(alice.sender.to_string()),
        grantee: Authority::Address(bob.sender.to_string()),
    };

   
    let json = actions[2].derive();

    // Not Ok: Another methods
    assert!(!key.actions.is_allowed(&ExecuteMsg::Purge {}));
    assert!(!key.actions.is_allowed(&ExecuteMsg::Freeze {}));
    assert!(!key.actions.is_allowed(&ExecuteMsg::TransferToken { 
        collection: String::from("collection"),
        token_id: String::from("token_id"),
        recipient: String::from("recipient"),
    }));


    // Not Ok:  Mint Token enforces the minter to be "Gimmy", "minter" or "sensei"
    assert!(!key.actions.is_allowed(&ExecuteMsg::MintToken {
        minter: bob.sender.to_string(),
        msg: None
    }));


    // Ok: Passed the minted check
    assert!(key.actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "Gimmy".to_string(),
        msg: None
    }));


    // Ok: Passed the json stringify check
    assert!(key.actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "sensei".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("to_address"),
            amount: vec![],
        }))
    }));

    // Not Ok: Even one field is different
    assert!(!key.actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "sensei".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("to_another_address"),
            amount: vec![],
        }))
    }));

    // Ok: Also work by passing the json manually
    assert!(key.actions.is_allowed_string(&json.to_string()));

}