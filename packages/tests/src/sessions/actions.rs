use std::fmt::Display;
use cosmwasm_schema::cw_serde;
use cw_storage_plus::Item;
use cosmwasm_std::{testing::{mock_dependencies, mock_env, mock_info}, BankMsg, CosmosMsg};
use saa_schema::with_session;
use serde::Serialize;
use smart_account_auth::{sessions::{
        action::{Action, Derivation, ActionName, ActionDerivation, AllowedActions},
        key::{SessionKey, Authority}
    }, 
    CredentialData
};

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

    #[strum(to_string = "{{\"transfer_token\":{{\"id\":\"{id}\",\"to\":\"{to}\"}}}}")]
    TransferToken {
        id: String,
        to: String,
    },

    UpdateAccountData {
        account_data: Option<CredentialData>,
    },

    #[strum(to_string = "freeeeeze")]
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
fn session_actions_simple() {
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
fn name_derived_actions() {

    let actions = AllowedActions::List(vec![
        Action::Derived(ActionDerivation { 
            message: ExecuteMsg::MintToken { minter: "alice".into(), msg: None }, 
            method: Derivation::Name,
        }),
        Action::Named(String::from("transfer_token"))
    ]);

    // Ok
    assert!(actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "bob".to_string(),
        msg: None
    }));

    // Ok
    assert!(actions.is_allowed(&ExecuteMsg::TransferToken { 
        id: String::from("id"),
        to: String::from("to"),
    }));

    // Not Ok
    assert!(!actions.is_allowed(&ExecuteMsg::Freeze {  }));
    assert!(!actions.is_allowed(&ExecuteMsg::Execute { msgs: vec![] }));

}






#[test]
fn string_derivations() {

    let actions = AllowedActions::List(vec![
        Action::Derived(ActionDerivation { 
            message: ExecuteMsg::MintToken { minter: "minter_contract".into(), msg: None }, 
            method: Derivation::String,
        }),
        Action::Derived(ActionDerivation { 
            message: ExecuteMsg::Execute { msgs: vec![] }, 
            method: Derivation::String,
        }),
        Action::Derived(ActionDerivation {
            message: ExecuteMsg::Freeze {}, 
            method: Derivation::String,
        })
    ]);
   

    // Not Ok: Another methods
    assert!(!actions.is_allowed(&ExecuteMsg::Purge {}));
    assert!(!actions.is_allowed(&ExecuteMsg::Freeze {}));
    assert!(!actions.is_allowed(&ExecuteMsg::TransferToken { 
        id: String::from("id"),
        to: String::from("to"),
    }));


    // Not Ok:  Includes `minter` which is set to "minter_contract" in the allowed action
    assert!(!actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "another_contract".to_string(),
        msg: None
    }));


    // Ok: Passed the minted check
    assert!(actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "minter_contract".to_string(),
        msg: None
    }));


    // Ok: Passed the minted check
    assert!(actions.is_allowed(&ExecuteMsg::Execute { msgs: vec![] }));


    let derived = ActionDerivation {
        message: ExecuteMsg::Execute { msgs: vec![] },
        method: Derivation::String,
    };

    println!("Derived: {}", derived);
    assert_eq!(derived.to_string(), "execute { msgs: [] }".to_string());
}




#[test]
fn json_derivations() {

    let transfer_msg = ExecuteMsg::TransferToken { 
        id: String::from("1"),
        to: String::from("alice"),
    };

    let transfer_action = Action::Derived(ActionDerivation { 
        message: transfer_msg.clone(),
        method: Derivation::Json,
    });

    let mint_action = Action::Derived(ActionDerivation { 
        message: ExecuteMsg::MintToken { 
            minter: "rock1...".into(), 
            msg: Some(CosmosMsg::Bank(BankMsg::Send {
                to_address: String::from("to_address"),
                amount: vec![],
            })), 
        },
        method: Derivation::Json,
    });


    let actions = AllowedActions::List(vec![
        mint_action,
        transfer_action
    ]);


    // Not Ok: Different id
    assert!(!actions.is_allowed(&ExecuteMsg::TransferToken { 
        id: String::from("2"),
        to: String::from("alice"),
    }));


    // Not Ok: Different recipient
    assert!(!actions.is_allowed(&ExecuteMsg::TransferToken { 
        id: String::from("1"),
        to: String::from("bob"),
    }));


    // Ok: Passed the minted check
    assert!(actions.is_allowed(&ExecuteMsg::TransferToken { 
        id: String::from("1"),
        to: String::from("alice"),
    }));


    // Ok: Passed the json stringify check
    assert!(actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "rock1...".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("rock1..."),
            amount: vec![],
        }))
    }));

    // Not Ok: Even one field is different
    assert!(!actions.is_allowed(&ExecuteMsg::MintToken {
        minter: "sensei".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("to_another_address"),
            amount: vec![],
        }))
    }));

    // Ok: Also work by passing the json manually
    assert!(actions.is_allowed(&transfer_msg.to_string()));
}



