use std::str::FromStr;

use cosmwasm_std::{testing::mock_env, Addr, Uint128};
use saa_common::{CredentialId, Expiration, SessionError};
use smart_account_auth::{messages::{Action, AllowedActions, CreateSession, CreateSessionFromMsg, DerivationMethod, SessionActionMsg, SessionInfo}, CredentialInfo, CredentialName};
use strum::IntoDiscriminant;

use crate::types::*;


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
    let res = create_msg.to_session(&env);
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
    let res = create_msg.to_session(&env);
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
    assert!(create_msg.to_session(&env).is_ok());


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
    let res = create_msg.to_session(&env);
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
    assert!(create_msg.to_session(&env).is_ok());



    // Error: Empty action list
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session(&env);
    assert_eq!(res.unwrap_err(), SessionError::EmptyCreateActions);



    // Error: Not an object that can deriva name from
    assert_eq!(
        Action::with_serde_name("not an object".to_string()).unwrap_err(), 
        SessionError::DerivationError
    );

    

    // Error: Just empty result
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_str(""),
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);


    // Error: At least one empty result
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_str(execute_msg.clone()),
            Action::with_str(""),
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);


    // Error: Duplicates
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_serde_name(execute_msg.clone()).unwrap(),
            Action::with_serde_name(execute_msg.clone()).unwrap()
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);



    // Success: Not really duplicates as the derivation methods are different
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_str(&execute_msg),
            Action::with_serde_name(&execute_msg).unwrap(),
            Action::with_serde_json(&execute_msg).unwrap(),
        ]),
        session_info: session_info.clone(),
    };
    assert!(create_msg.to_session(&env).is_ok());


    // Error: Different messages but in the end it's the same derivations -> Duplicates
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_strum_name(execute_msg.clone()),
            Action::with_strum_name(simple_execute_msg.clone()),
        ]),
        session_info: session_info.clone(),
    };
    let res = create_msg.to_session(&env);
    assert_eq!(res.unwrap_err(), SessionError::InvalidActions);



    // Success: Methods are same but the end json string results are different
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_serde_json(&execute_msg).unwrap(),
            Action::with_serde_json(&simple_execute_msg).unwrap(),
        ]),
        session_info: session_info.clone(),
    };
    assert!(create_msg.to_session(&env).is_ok());



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

    println!("Before session");

    // Default to DerivationMethod::Name
    let session_key = CreateSessionFromMsg {
        derivation_method: None,
        message: mint_msg.clone(),
        session_info: session_info.clone(),
    }.to_session(&env).unwrap();


    // ok: same message
    assert!(session_key.actions.is_message_allowed(&mint_msg));
    // ok: same message name
    assert!(session_key.actions.is_message_allowed(&changed_mint_msg));
    // err: different name
    assert!(!session_key.actions.is_message_allowed(&diff_msg));


    // Strum  ToString
    let session_key = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::String),
        message: mint_msg.clone(),
        session_info: session_info.clone(),
    }.to_session(&env).unwrap();


    // ok: inner message doesn't affect to_string() output
    assert!(session_key.actions.is_message_allowed(&not_bob_mint_msg));
    // err: minter address is different which affects the result of to_string()
    assert!(!session_key.actions.is_message_allowed(&changed_mint_msg));


    // Serde Json
    let session_key = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::Json),
        message: mint_msg.clone(),
        session_info: session_info.clone(),
    }.to_session(&env).unwrap();


    // ok: same message
    assert!(session_key.actions.is_message_allowed(&mint_msg));
    // err: even one small innner field changed
    assert!(!session_key.actions.is_message_allowed(&tiny_change_mint_msg));


}


fn create_session_error(msg: &CreateSession) -> SessionError {
    msg.to_session(&mock_env()).unwrap_err()
}

fn create_from_error(msg: &CreateSessionFromMsg<ExecuteMsg>) -> SessionError {
    msg.to_session(&mock_env()).unwrap_err()
}


#[test]
fn nested_session_message_checks() {
    let env = mock_env();

    let mint_msg = ExecuteMsg::MintToken {
        minter: "minter_contract".to_string(),
        msg: Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: String::from("bob"),
            amount: vec![Coin {
                denom: "denom".to_string(),
                amount: Uint128::new(100),
            }],
        })),
    };

    let session_info: SessionInfo = SessionInfo {
        expiration: None,
        granter: None,
        grantee: ("alice".to_string(), CredentialInfo {
            name: CredentialName::Native,
            hrp: None,
            extension: None
        }),
    };


    let create_session_name = CreateSession {
        allowed_actions: AllowedActions::Include(vec![Action::with_strum_name(mint_msg.clone())]),
        session_info: session_info.clone(),
    };
    
    let create_session_str = CreateSession {
        allowed_actions: AllowedActions::Include(vec![Action::with_str(mint_msg.clone())]),
        session_info: session_info.clone(),
    };

    let create_session_json = CreateSession {
        allowed_actions: AllowedActions::Include(vec![Action::with_serde_json(mint_msg.clone()).unwrap()]),
        session_info: session_info.clone(),
    };


    let create_from_name = CreateSessionFromMsg {
        derivation_method: None,
        message: mint_msg.clone(),
        session_info: session_info.clone(),
    };

    let create_from_str = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::String),
        message: mint_msg.clone(),
        session_info: session_info.clone(),
    };

    let create_from_json = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::Json),
        message: mint_msg.clone(),
        session_info: session_info.clone(),
    };


    let create_session_nested_self = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_strum_name(ExecuteMsg::SessionActions(Box::new(
                SessionActionMsg::CreateSession(create_session_str.clone())
            )))
        ]),
        session_info: session_info.clone(),
    };

    let create_session_nested_from = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_strum_name(ExecuteMsg::SessionActions(Box::new(
                SessionActionMsg::CreateSessionFromMsg(create_from_str.clone())
            ))),
        ]),
        session_info: session_info.clone(),
    };

    let create_session_all = CreateSession {
        allowed_actions: AllowedActions::All {},
        session_info: session_info.clone(),
    };


    let create_from_nested_create = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::Name),
        message: ExecuteMsg::SessionActions(Box::new(
            SessionActionMsg::CreateSession(create_session_str.clone())
        )),
        session_info: session_info.clone(),
    };

    let create_from_nested_from = CreateSessionFromMsg {
        derivation_method: Some(DerivationMethod::Name),
        message: ExecuteMsg::SessionActions(Box::new(
            SessionActionMsg::CreateSessionFromMsg(create_from_str.clone())
        )),
        session_info: session_info.clone(),
    };


    use SessionError::InnerSessionAction;

    // Normal messages work as expected
    assert!(create_session_name.to_session(&env).is_ok());
    assert!(create_session_str.to_session(&env).is_ok());
    assert!(create_session_json.to_session(&env).is_ok());
    assert!(create_from_name.to_session(&env).is_ok());
    assert!(create_from_str.to_session(&env).is_ok());
    assert!(create_from_json.to_session(&env).is_ok());

    // All nested CresateSession messages should fail
    assert_eq!(create_session_error(&create_session_nested_self), InnerSessionAction);
    assert_eq!(create_session_error(&create_session_nested_from), InnerSessionAction);

    // All nested CreateSessionFromMsg should fail
    assert_eq!(create_from_error(&create_from_nested_create), InnerSessionAction);
    assert_eq!(create_from_error(&create_from_nested_from), InnerSessionAction);



    // Creating a session with AllowedActions::All 
    let allowed = create_session_all.to_session(&env).unwrap().actions;

    
    // none of the session messages should be allowed despite AllowedActions::All
    assert!(!allowed.is_message_allowed(&create_session_name));
    assert!(!allowed.is_message_allowed(&create_session_str));
    assert!(!allowed.is_message_allowed(&create_session_json));
    assert!(!allowed.is_message_allowed(&create_from_name));
    assert!(!allowed.is_message_allowed(&create_from_str));
    assert!(!allowed.is_message_allowed(&create_from_json));


    // strum name should work identical to is_message_allowed
    assert!(!allowed.is_action_allowed(&Action::with_strum_name(create_session_nested_self.clone())));
    assert!(!allowed.is_action_allowed(&Action::with_strum_name(create_from_nested_create.clone())));


    // both are struct with custom Display implemntation that returns only the name
    // practically the same as strum name
    assert!(!allowed.is_action_allowed(&Action::with_str(create_session_nested_self.clone())));
    assert!(!allowed.is_action_allowed(&Action::with_str(create_from_nested_create.clone())));


    // json is very tricky: as messages work fine
    assert!(!allowed.is_message_allowed(&create_session_nested_self.clone()));
    assert!(!allowed.is_message_allowed(&create_session_nested_from.clone()));


    // checking json for containing `session_info` in the result
    assert!(!allowed.is_action_allowed(&Action::with_serde_json(create_session_nested_self.clone()).unwrap())); 
    assert!(!allowed.is_action_allowed(&Action::with_serde_json(create_from_nested_create.clone()).unwrap()));


    // wrap in execute message
    let create_session_nested_exec = ExecuteMsg::SessionActions(Box::new(
        SessionActionMsg::CreateSession(create_session_nested_self.clone())
    ));
    let create_from_nested_exec = ExecuteMsg::SessionActions(Box::new(
        SessionActionMsg::CreateSessionFromMsg(create_from_nested_create.clone())
    ));
    assert!(!allowed.is_action_allowed(&Action::with_serde_json(create_session_nested_exec.clone()).unwrap()));
    assert!(!allowed.is_action_allowed(&Action::with_serde_json(create_from_nested_exec.clone()).unwrap()));

    // normal messages should be allowed
    assert!(allowed.is_message_allowed(&mint_msg));
}



#[test]
fn macro_strum_derivations_work() {

    let session_info: SessionInfo = SessionInfo {
        expiration: None,
        granter: None,
        grantee: ("alice".to_string(), CredentialInfo {
            name: CredentialName::Native,
            hrp: None,
            extension: None
        }),
    };

    let msg = ExecuteMsg::Freeze {  };


    // Custom implementation of Display and IntoDiscriminant to reduce attack vector
    let create_msg = CreateSession {
        allowed_actions: AllowedActions::Include(vec![
            Action::with_strum_name(msg.clone())
        ]),
        session_info: session_info.clone(),
    };

    let expected = "session_actions";
    let exec_create = ExecuteMsg::SessionActions(Box::new(
        SessionActionMsg::CreateSession(create_msg.clone())
    ));
    let exec_name = exec_create.discriminant().to_string();
    let exec_str = exec_create.to_string();
    assert!(exec_name == exec_str && exec_name == expected);
    

    let exec_discr = exec_create.discriminant();
    let exec_from_str = <ExecuteMsg as IntoDiscriminant>
            ::Discriminant::from_str(&exec_name).unwrap();
    assert!(exec_discr == exec_from_str);
    
}