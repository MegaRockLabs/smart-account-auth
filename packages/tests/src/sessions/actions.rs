use std::str::FromStr;
use cosmwasm_std::{testing::{message_info, mock_env}, Addr};
use smart_account_auth::{
    Session, Expiration,CredentialInfo, CredentialName,
    msgs::{Action, AllowedActions},
};
use crate::types::{BankMsg, CosmosMsg, ExecuteMsg};




#[test]
fn session_actions_simple() {
    let env = mock_env();
    let alice = message_info(&Addr::unchecked("alice"), &[]);
    let bob = message_info(&Addr::unchecked("bob"), &[]);

    let actions = vec![
        Action::from_str("mint_token").unwrap(), 
        Action::from_str("transfer_token").unwrap(),
    ];

    let key = Session {
        actions: AllowedActions::Include(actions),
        expiration: Expiration::AtHeight(env.block.height + 100),
        granter: alice.sender.to_string(),
        grantee: (bob.sender.to_string(), CredentialInfo::from_name(CredentialName::Native)),
        nonce: 0,
    };

    let msg = ExecuteMsg::MintToken {
        minter: bob.sender.to_string(),
        msg: None
    };

    if key.expiration.is_expired(&env.block) {
        panic!("Session key expired");
    }

    assert!(key.actions.can_do_action(&Action::with_strum_name(msg)));

}





#[test]
fn name_derived_actions() {

    let actions = AllowedActions::Include(vec![
        Action::with_strum_name(ExecuteMsg::MintToken { 
            minter: "alice".into(), 
            msg: None 
        }),
        Action::from_str("transfer_token").unwrap(),
    ]);

    // Ok
    assert!(actions.can_do_action(&Action::with_strum_name(
        ExecuteMsg::MintToken {
            minter: "bob".to_string(),
            msg: None
        }
    )));

    // Ok
    assert!(actions.can_do_action(&Action::with_strum_name(
        ExecuteMsg::TransferToken { 
            id: String::from("id"),
            to: String::from("to"),
    })));

    // Not Ok
    assert!(!actions.can_do_str(&Action::with_strum_name(
        ExecuteMsg::Freeze {  }
    )));
    assert!(!actions.can_do_str(&Action::with_strum_name(
        ExecuteMsg::Execute { msgs: vec![] }
    )));

}






#[test]
fn string_derivations() {

    let actions = AllowedActions::Include(vec![
        Action::with_str(ExecuteMsg::MintToken { 
            minter: "minter_contract".into(), 
            msg: None 
        }), 
        Action::with_str(ExecuteMsg::Execute { msgs: vec![] }), 
        Action::with_str(ExecuteMsg::Purge { })
    ]);
   

    // Not Ok: Other methods
    assert!(!actions.can_do_str(&ExecuteMsg::Freeze {}));
    assert!(!actions.can_do_str(&ExecuteMsg::TransferToken { 
        id: String::from("id"),
        to: String::from("to"),
    }));


    // Not Ok:  Minter is included and equal to "minter_contract"
    assert!(!actions.can_do_str(&ExecuteMsg::MintToken {
        minter: "another_contract".to_string(),
        msg: None
    }));


    // Ok: All good
    assert!(actions.can_do_str(&ExecuteMsg::MintToken {
        minter: "minter_contract".to_string(),
        msg: None
    }));


    // Ok: Passed the minted check
    assert!(actions.can_do_str(&ExecuteMsg::Execute { msgs: vec![] }));


    let derived = Action::with_str(ExecuteMsg::Execute { 
        msgs: vec![] 
    });

    // Ok: Default to name as not customised
    assert_eq!(derived.to_string(), "execute".to_string());
}




#[test]
fn json_derivations() {

    let transfer_msg = ExecuteMsg::TransferToken { 
        id: String::from("1"),
        to: String::from("alice"),
    };

    let mint_msg = ExecuteMsg::MintToken { 
        minter: "rock1...".into(), 
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("to_address"),
            amount: vec![],
        })), 
    };


    let mint_action = Action::with_serde_json(mint_msg.clone()).unwrap();
    let transfer_action = Action::with_serde_json(transfer_msg.clone()).unwrap();


    let actions = AllowedActions::Include(vec![mint_action, transfer_action]);


    // Not Ok: Different id
    assert!(!actions.can_do_json(&ExecuteMsg::TransferToken { 
        id: String::from("2"),
        to: String::from("alice"),
    }));


    // Not Ok: Different recipient
    assert!(!actions.can_do_json(&ExecuteMsg::TransferToken { 
        id: String::from("1"),
        to: String::from("bob"),
    }));


    // Ok: Passed the minted check
    assert!(actions.can_do_json(&ExecuteMsg::TransferToken { 
        id: String::from("1"),
        to: String::from("alice"),
    }));


    // Ok: Passed the json stringify check
    assert!(actions.can_do_json(&ExecuteMsg::MintToken {
        minter: "rock1...".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("to_address"),
            amount: vec![],
        }))
    }));

    // Not Ok: Even one field is different
    assert!(!actions.can_do_json(&ExecuteMsg::MintToken {
        minter: "sensei".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("to_another_address"),
            amount: vec![],
        }))
    }));


    // Not Ok: to_string() includes extra spaces and doesn include msg
    assert!(!actions.can_do_action(&Action::with_str(mint_msg)));

    // Not Ok: the result of to_string() and serde_json::to_string() are identical
    // but the method is nevertheless different
    assert!(!actions.can_do_action(&Action::with_str(transfer_msg)));

}


