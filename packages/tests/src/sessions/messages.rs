use cosmwasm_std::{testing::mock_env, Addr, Uint128};
use saa_common::{CredentialId, Expiration, SessionError};
use smart_account_auth::{messages::{Action, AllowedActions, CreateSession, CreateSessionFromMsg, DerivationMethod, SessionInfo}, CredentialInfo, CredentialName};

use crate::types::{BankMsg, Coin, CosmosMsg, ExecuteMsg};


#[test]
fn simple_create_session_messages() {

    let env = mock_env();
    let alice = Addr::unchecked("alice");

    let execute_msg = ExecuteMsg::Execute { msgs: vec![] };
    let simple_execute_msg = ExecuteMsg::Execute { msgs: vec![CosmosMsg::Simple {}] };

    // Error: Invalid Grantee
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::All {},
        session_info: SessionInfo {
            expiration: None,
            granter: None,
            grantee: (CredentialId::default(), CredentialInfo {
                name: CredentialName::Native,
                hrp: None,
                extension: None
            }),
        },
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidGrantee);


    // Error: Granter == Grantee
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::All {},
        session_info: SessionInfo {
            expiration: None,
            granter: Some(alice.to_string()),
            grantee: (alice.to_string(), CredentialInfo {
                name: CredentialName::Native,
                hrp: None,
                extension: None
            }),
        },
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidGranter);

    

    // Success
    let alice = Addr::unchecked("alice");
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::All {},
        session_info: SessionInfo {
            expiration: None,
            granter: None,
            grantee: (alice.to_string(), CredentialInfo {
                name: CredentialName::Native,
                hrp: None,
                extension: None
            }),
        },
    };
    assert!(create_msg.to_session_key(&env).is_ok());


    // Error: Expiration already expired
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::All {},
        session_info: SessionInfo {
            expiration: Some(Expiration::AtHeight(env.block.height)),
            granter: None,
            grantee: (alice.to_string(), CredentialInfo {
                name: CredentialName::Native,
                hrp: None,
                extension: None
            }),
        },
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::Expired);



    // Success: Expiration is fine now
    let session_info = SessionInfo {
        expiration: Some(Expiration::AtHeight(env.block.height + 1)),
        granter: None,
        grantee: (alice.to_string(), CredentialInfo {
            name: CredentialName::Native,
            hrp: None,
            extension: None
        }),
    };
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::All {},
        session_info: session_info.clone(),
    };
    assert!(create_msg.to_session_key(&env).is_ok());



    // Error: Empty action list
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::List(vec![]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::EmptyActions);



    // Error: Not an object that can deriva name from
    assert_eq!(
        Action::with_serde_name("not an object".to_string()).unwrap_err(), 
        SessionError::DerivationError
    );

    

    // Error: Just empty result
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::List(vec![
            Action::with_str(""),
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);


    // Error: At least one empty result
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::List(vec![
            Action::with_str(execute_msg.clone()),
            Action::with_str(""),
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);


    // Error: Duplicates
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::List(vec![
            Action::with_serde_name(execute_msg.clone()).unwrap(),
            Action::with_serde_name(execute_msg.clone()).unwrap()
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);



    // Success: Not really duplicates as the derivation methods are different
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::List(vec![
            Action::with_str(&execute_msg),
            Action::with_serde_name(&execute_msg).unwrap(),
            Action::with_serde_json(&execute_msg).unwrap(),
        ]),
        session_info: session_info.clone(),
    };
    assert!(create_msg.to_session_key(&env).is_ok());


    // Error: Different messages but in the end it's the same derivations -> Duplicates
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::List(vec![
            Action::with_strum_name(execute_msg.clone()),
            Action::with_strum_name(simple_execute_msg.clone()),
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session_key(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);



    // Success: Methods are same but the end json string results are different
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::List(vec![
            Action::with_serde_json(&execute_msg).unwrap(),
            Action::with_serde_json(&simple_execute_msg).unwrap(),
        ]),
        session_info: session_info.clone(),
    };
    assert!(create_msg.to_session_key(&env).is_ok());



}






#[test]
fn generating_session_from_messages() {

    let env = mock_env();

    let mint_msg_msg = Some(CosmosMsg::Bank(BankMsg::Send {
        to_address: String::from("bob"),
        amount: vec![Coin {
            denom: "denom".to_string(),
            amount: Uint128::new(100),
        }],
    }));

    let mint_msg = ExecuteMsg::MintToken {
        minter: "minter_contract".to_string(),
        msg: mint_msg_msg.clone(),
    };

    let changed_mint_msg = ExecuteMsg::MintToken {
        minter: "changed_minter_contract".to_string(),
        msg: mint_msg_msg
    };


    let not_bob_mint_msg = ExecuteMsg::MintToken {
        minter: "minter_contract".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("not_bob"),
            amount: vec![Coin {
                denom: "denom".to_string(),
                amount: Uint128::new(100),
            }],
        })),
    };

    let tiny_change_mint_msg = ExecuteMsg::MintToken {
        minter: "minter_contract".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("bob"),
            amount: vec![Coin {
                denom: "Denom".to_string(),
                amount: Uint128::new(100),
            }],
        })),
    };


    let diff_msg = ExecuteMsg::Freeze {};



    let session_info: SessionInfo = SessionInfo {
        expiration: None,
        granter: None,
        grantee: ("alice".to_string(), CredentialInfo {
            name: CredentialName::Native,
            hrp: None,
            extension: None
        }),
    };


    // Default to DerivationMethod::Name
    let session_key = CreateSessionFromMsg {
        derivation_method: None,
        message: Box::new(mint_msg.clone()),
        session_info: session_info.clone(),
    }.to_session_key(&env).unwrap();

    // ok: same message
    assert!(session_key.actions.is_message_allowed(&mint_msg));
    // ok: same message name
    assert!(session_key.actions.is_message_allowed(&changed_mint_msg));
    // err: different name
    assert!(!session_key.actions.is_message_allowed(&diff_msg));


    // Strum  ToString
    let session_key = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::String),
        message: Box::new(mint_msg.clone()),
        session_info: session_info.clone(),
    }.to_session_key(&env).unwrap();


    // ok: inner message doesn't affect to_string() output
    assert!(session_key.actions.is_message_allowed(&not_bob_mint_msg));
    // err: minter address is different which affects the result of to_string()
    assert!(!session_key.actions.is_message_allowed(&changed_mint_msg));


    // Serde Json
    let session_key = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::Json),
        message: Box::new(mint_msg.clone()),
        session_info: session_info.clone(),
    }.to_session_key(&env).unwrap();


    // ok: same message
    assert!(session_key.actions.is_message_allowed(&mint_msg));
    // err: even one small innner field changed
    assert!(!session_key.actions.is_message_allowed(&tiny_change_mint_msg));
}