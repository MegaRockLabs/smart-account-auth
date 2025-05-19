


use saa_common::{from_json, Binary};
use cw_auths::{ 
    CreateSession, CreateSessionFromMsg, QueryUsesActions, 
    RevokeKeyMsg, SessionActionMsg, SessionQueryMsg,
    handle_session_actions, handle_session_queries,
    saa_types::{
        msgs::{Action, ActionDerivation, AllQueryDerivation, AllowedActions}, 
        SessionInfo, CredentialInfo, CredentialName,
        AuthError, SessionError, Expiration
    }
};

use cosmwasm_std::{
    ensure, testing::{message_info, mock_dependencies, mock_env, MockApi}, 
    Api, Env, Response, StdError, StdResult, Storage, Uint128
};
use crate::{
    types::{BankMsg, Coin, CosmosMsg, ExecuteMsg, QueryMsg, StakingMsg}, 
    utils::{session_info, session_query, with_key_msg, ALICE_ADDR, EVE_ADDR}
};
use strum::{IntoDiscriminant, VariantArray, VariantNames};


const ADMIN : &str = ALICE_ADDR;



pub fn execute(
    api : &dyn cosmwasm_std::Api,
    storage: &mut dyn cosmwasm_std::Storage,
    env: &cosmwasm_std::Env,
    info: &cosmwasm_std::MessageInfo,
    msg: ExecuteMsg,
) -> Result<cosmwasm_std::Response, AuthError> {
    let (session, inner_msgs) = handle_session_actions(
        api, 
        storage, 
        env, 
        info, 
        msg,
        None
    )?;

    match (inner_msgs.len(), session) {

        (0, None) => return Ok(Response::new()
            .add_attribute("action", "session_revoked")
        ),

        (0, Some(session)) => return Ok(Response::new()
            .add_attribute("action", "session_created")
            .add_attribute("session_key", session.key().as_str())
            .add_attribute("nonce", session.nonce.to_string().as_str())
        ),

        (1, None) => {
            ensure!(info.sender.as_str() == ADMIN, StdError::generic_err("Unauthorized to call directly"));
            execute_logic(api, storage, env, info, inner_msgs[0].clone())
        },

        (_, Some(session)) => {
            let mut res = Response::new();
            let mut sub_msgs = vec![];


            for msg in inner_msgs.into_iter() {
                
                let msg_res = execute_logic(api, storage, env, info, msg)?;
                sub_msgs.extend(msg_res.messages.clone());
                res = res.add_events(msg_res.events)
                        .add_attributes(msg_res.attributes);
                if let Some(data) = msg_res.data {
                    res = res.set_data(data);
                }
            }
            return Ok(res
                .add_submessages(sub_msgs)
                .add_attribute("session_key", session.key().as_str())
                .add_attribute("nonce", session.nonce.to_string().as_str())
            );
        },

        (_, _) => unreachable!()
    }

}


pub fn execute_logic(
    _api : &dyn cosmwasm_std::Api,
    _storage: &mut dyn cosmwasm_std::Storage,
    _env: &cosmwasm_std::Env,
    _info: &cosmwasm_std::MessageInfo,
    msg: ExecuteMsg,
) -> Result<cosmwasm_std::Response, AuthError> {
    
    match msg {

        ExecuteMsg::MintToken { minter, .. } => {
            // Handle mint token logic
            Ok(Response::default()
                .add_attribute("status", "minted")
                .add_attribute("minter", minter)
            )
        },

        ExecuteMsg::TransferToken { id, to } => {
            // Handle transfer token logic
            Ok(Response::default()
                .add_attribute("status", "transferred")
                .add_attribute("to", to)
                .add_attribute("id", id)
            )
        },

        ExecuteMsg::Execute { msgs } => {
            // Handle execute logic
            Ok(Response::default()
                .add_attribute("status", "executed")
                .add_attribute("msg_len", msgs.len().to_string())
            )
        },

        ExecuteMsg::Freeze {  } => {
            // Handle freeze logic
            Ok(Response::default()
                .add_attribute("status", "frozen")
            )
        },

        ExecuteMsg::Purge {  } => {
            // Handle purge logic
            Ok(Response::default()
                .add_attribute("status", "purged")
            )
        },

        m => {
            println!("Unrecognized message: {:?}", m);
            unreachable!("CreateSession should be handled in execute")
        },
    }
}




pub fn query(
    api : &dyn Api,
    storage: &dyn Storage,
    env: &Env, 
    msg: QueryMsg
) -> StdResult<Binary> {

    if let Some(res) = handle_session_queries(api, storage, env, &msg)? {
        return Ok(res);
    }

    match msg {

        QueryMsg::GetBalance {  } => {
            // Handle get balance logic
            Ok(Binary::default())
        },

        _ => {
            println!("Unrecognized message: {:?}", msg);
            unreachable!("CreateSession should be handled in execute")
        },
        
    }

}




#[test]
fn simple_contract_flow() {

    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let mut env = mock_env();
    let api = MockApi::default();

    let alice_addr = api.addr_make("alice");
    let alice = message_info(&alice_addr, &vec![]);

    let bob_addr = api.addr_make("bob");
    let bob = message_info(&bob_addr, &vec![]);

    let eve_addr = api.addr_make("eve");
    let eve = message_info(&eve_addr, &vec![]);

    let env = &mut env;
    let alice = &alice;
    let bob = &bob;
    let eve = &eve;

    // Alice can call messages directly
    assert!(execute(deps.api, deps.storage, env, alice, ExecuteMsg::Purge {}).is_ok());


    // Other addresses can't
    assert!(execute(deps.api, deps.storage, env, bob, ExecuteMsg::Purge {}).is_err());
    assert!(execute(deps.api, deps.storage, env, eve, ExecuteMsg::Purge {}).is_err());


    // Alice can create session key for bob
    let allowed_actions = AllowedActions::Include(vec![
        Action::with_str(ExecuteMsg::MintToken { 
            minter: "minter_contract".into(), 
            msg: None 
        }), 
        Action::with_str(ExecuteMsg::Execute { msgs: vec![CosmosMsg::Simple {}] }), 
        Action::with_str(ExecuteMsg::Purge { })
    ]);

    // session_info contains bob as native caller
    let mut session = CreateSession {
        allowed_actions: allowed_actions.clone(),
        session_info: session_info(),
    };
    session.session_info.expiration = Some(Expiration::AtHeight(env.block.height + 100));


    let msg = ExecuteMsg::SessionActions(Box::new(SessionActionMsg::CreateSession(session.clone())));

    // Calling smart contract here finally
    let res = execute(deps.api, deps.storage, env, alice, msg).unwrap();

    let found_key = res.attributes
        .into_iter()
        .find(|attr| attr.key.contains("session_key"))
        .unwrap()
        .value;

    // contract set alice as granter, without it keys don't match
    let no_alice = session.to_session(&env).unwrap().key();
    assert!(found_key != no_alice);

    // if we set it we can predict what the key value is going to be to send multiple messages in a batch
    session.session_info.granter = Some(alice_addr.to_string());
    let expected = session.to_session(&env).unwrap().key();
    assert_eq!(found_key, expected);

    let found_key = &found_key;


    // Now Bob should be able to use the session key
    let exec_msg = with_key_msg(ExecuteMsg::MintToken { 
            minter: "minter_contract".into(), 
            msg: None 
        }, 
        &found_key.clone()
    );

    let res = execute(deps.api, deps.storage, env, bob, exec_msg.clone()).unwrap();

    // All good
    let minted = res.attributes
        .into_iter()
        .any(|attr| attr.key.contains("status") && attr.value.contains("minted"));

    assert!(minted);    


    // Eve can't do it even with the same message
    let eve_res = execute(deps.api, deps.storage, env, eve, exec_msg.clone());
    assert_eq!(eve_res.unwrap_err(), SessionError::NotGrantee.into());



    // This is allowed message but Bob can't call it directly
    assert!(execute(deps.api, deps.storage, env, bob, ExecuteMsg::Purge {}).is_err());

    // He needs to always wrap it using WithSessionKey wrapper  and then it works
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(ExecuteMsg::Purge {}, found_key)).is_ok());


    // Bob can't do it with minter address change even a tiny bit
    let exec_msg = with_key_msg(ExecuteMsg::MintToken { 
            minter: "minter_contractt".into(), 
            msg: None 
        }, found_key
    );
    let res = execute(deps.api, deps.storage, env, bob, exec_msg.clone());
    assert_eq!(res.unwrap_err(), SessionError::NotAllowedAction.into());



    // Bob can do ExecuteMsg::Execute  that is not identical to one in the allowed list
    // cause it was specified to use name for derivation
    let exec_msg = with_key_msg(ExecuteMsg::Execute { msgs: vec![] }, found_key);
    let res = execute(deps.api, deps.storage, env, bob, exec_msg.clone());
    assert!(res.is_ok());



    // Bob can't do other messages
    let exec_msg = with_key_msg(ExecuteMsg::Freeze {}, found_key); 
    let res = execute(deps.api, deps.storage, env, bob, exec_msg.clone());
    assert!(res.is_err());


    // later when time passed out seesion key get expired and deleted
    env.block.height += 101;


    // Bob can't use the old valid message anymore
    let exec_msg = with_key_msg(ExecuteMsg::MintToken {
            minter: "minter_contract".into(), 
            msg: None
        }, 
        found_key
    );

    assert!(execute(deps.api, deps.storage, env, bob, exec_msg.clone()).is_err());
   
}
   



#[test]
fn from_message_and_revoking() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let api = MockApi::default();
    let env = mock_env();

    let alice_addr = api.addr_make("alice");
    let alice = message_info(&alice_addr, &vec![]);
    let bob_addr = api.addr_make("bob");
    let bob = message_info(&bob_addr, &vec![]);
    let eve_addr = api.addr_make("eve");
    let eve = message_info(&eve_addr, &vec![]);


    let msg = ExecuteMsg::Execute { msgs: vec![CosmosMsg::Simple {}] };
    let alice = &alice;
    let env = &env;

    let from_msg = ExecuteMsg::SessionActions(Box::new(SessionActionMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: msg.clone(),
        derivation: Some(ActionDerivation::Json),
        session_info: session_info(),
    })));

    let res = execute(deps.api, deps.storage, env, alice, from_msg.clone()).unwrap();
    let key = res.attributes
        .iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .clone()
        .value;



    let executed_too = res.attributes
        .iter()
        .any(|attr| attr.key.contains("status") && attr.value.contains("executed"));

    let msg_len_one = res.attributes
        .iter()
        .any(|attr| attr.key.contains("msg_len") && attr.value == "1");

    // Got key but executed the message at the same time
    assert!(executed_too && msg_len_one);

    
    
    // with JSON derication only identical message goes through
    let msg2 = ExecuteMsg::Execute { msgs: vec![] };
    let msg3 = ExecuteMsg::Execute { msgs: vec![CosmosMsg::Bank(
        BankMsg::Send {to_address: EVE_ADDR.to_string(), amount: vec![]}
    )]};
    let msg4 = ExecuteMsg::Execute { msgs: vec![
        CosmosMsg::Simple { }, 
        CosmosMsg::Simple { }, 
        CosmosMsg::Staking(StakingMsg::Delegate { 
            validator: "POSERS".to_string(), 
            amount: Coin { denom: "atom".to_string(), amount: Uint128::from(1_000_000_000u128) } 
        }),
        CosmosMsg::Bank(BankMsg::Send {
            to_address: EVE_ADDR.to_string(), 
            amount: vec![Coin { denom: "btc".to_string(), amount: Uint128::from(1_000_000_000u128) } ]
        }),
        CosmosMsg::Simple { }, 
    ]};

    let bob = &bob;
    let eve = &eve;
    let key = &key;

    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg2.clone(), key)).is_err());
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg3.clone(), key)).is_err());
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg4.clone(), key)).is_err());


    // the identical message goes through
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg.clone(), key)).is_ok());

    
    // Alice can try creating another session key for Bob without changing anything
    let from_msg = ExecuteMsg::SessionActions(Box::new(SessionActionMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: msg.clone(),
        derivation: Some(ActionDerivation::Json),
        session_info: session_info(),
    })));

    let res = execute(deps.api, deps.storage, env, alice, from_msg.clone()).unwrap();
    let new_key = res.attributes
        .iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .clone()
        .value;

    // If params didn't change the key will be identical. However you can use this to override the expiration or creation date
    assert_eq!(*key, new_key);


    // Not let's create another key where actions are detived usoing the message name
    let from_msg = ExecuteMsg::SessionActions(Box::new(SessionActionMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: msg.clone(),
        derivation: None,
        session_info: session_info(),
    })));

    
    let res = execute(deps.api, deps.storage, env, alice, from_msg.clone()).unwrap();
    let exec_name_key = res.attributes
        .iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .clone()
        .value;

    // Action list is different so the key should be different
    assert!(*key != exec_name_key);



    // Bob can still use the old key
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg.clone(), key)).is_ok());


    let exec_name_key = &exec_name_key;
    // But now with the second he can do any execute message he could do before
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg2.clone(), exec_name_key)).is_ok());
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg3.clone(), exec_name_key)).is_ok());




    let res = execute(deps.api, deps.storage, env, bob, 
        with_key_msg(msg4.clone(), exec_name_key)
    ).unwrap();
    

    let msg_len = res.attributes
        .iter()
        .find(|attr| attr.key.contains("msg_len"))
        .unwrap()
        .clone()
        .value;

    assert_eq!(msg_len, "5");
    


    // Let's revoke the first key now
    let revoke_msg = ExecuteMsg::SessionActions(
        Box::new(SessionActionMsg::RevokeSession(RevokeKeyMsg {
            session_key: key.to_string(),
        })
    ));

    
    // Bob can't revoke it
    assert!(execute(deps.api, deps.storage, env, bob, revoke_msg.clone()).is_err());

    // Alice can 
    let res = execute(deps.api, deps.storage, env, alice, revoke_msg.clone()).unwrap();


    let status_ok = res.attributes.iter().any(|attr| 
        attr.key.contains("action") && attr.value.contains("revoked")
    );
    assert!(status_ok);


    // Bob can't use the old key anymore
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg.clone(), key)).is_err());


    // Can still use the latest 
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg.clone(), exec_name_key)).is_ok());



    // Let's create a key for Eve with identical allowed actions
    let from_msg = ExecuteMsg::SessionActions(Box::new(
        SessionActionMsg::CreateSessionFromMsg(CreateSessionFromMsg {
            message: msg.clone(),
            derivation: None,
            session_info: SessionInfo { 
                grantee: (eve_addr.to_string(), CredentialInfo { 
                    name: CredentialName::Native, 
                    hrp: None, 
                    extension: None
                }), 
                granter: None, 
                expiration: None
            },
    })));

    
    let res = execute(deps.api, deps.storage, env, alice, from_msg.clone()).unwrap();
    let eve_key = res.attributes
        .iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .clone()
        .value;


    let eve_key = &eve_key;

    // Eve's key is different from Bob and they can't use each other keys
    assert!(eve_key != exec_name_key);


    // Bob can't use Eve's key
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg.clone(), eve_key)).is_err());

    // Eve can't use Bob's key
    assert!(execute(deps.api, deps.storage, env, eve, with_key_msg(msg.clone(), exec_name_key)).is_err());



    // Bob can use his own key
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg.clone(), exec_name_key)).is_ok());

    // Eve can use her own key
    assert!(execute(deps.api, deps.storage, env, eve, with_key_msg(msg.clone(), eve_key)).is_ok());


    // Let's revoke Bob's key again
    execute(deps.api, deps.storage, env, alice, ExecuteMsg::SessionActions(
        Box::new(SessionActionMsg::RevokeSession(RevokeKeyMsg { session_key: exec_name_key.to_string() }))
    )).unwrap();


    // Bob can't use any of his keys anymore
    assert!(execute(deps.api, deps.storage, env, bob, with_key_msg(msg.clone(), exec_name_key)).is_err());

    // Eve still can use hers
    assert!(execute(deps.api, deps.storage, env, eve, with_key_msg(msg.clone(), eve_key)).is_ok());


}
    



#[test]
fn deriving_message_queries() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let env = mock_env();

    let msg = ExecuteMsg::MintToken { 
        minter: "jeremy".into(), 
        msg: Some(CosmosMsg::Simple {})
    };
    

    let name_res : String = from_json(&query(deps.api, deps.storage, &env, 
        session_query(
                SessionQueryMsg::Derive { 
                    method: Some(ActionDerivation::Name),
                    message: msg.clone(),
                }
            )
        ).unwrap()
    ).unwrap();
    assert_eq!(name_res, "mint_token");


    let str_res : String = from_json(&query(deps.api, deps.storage, &env, 
        session_query(
                SessionQueryMsg::Derive { 
                    method: Some(ActionDerivation::String),
                    message: msg.clone(),
                }
            )
        ).unwrap()
    ).unwrap();
    assert_eq!(str_res, r#"{ "mint_token": { "minter": "jeremy" } }"#);


    let json_res : String = from_json(&query(deps.api, deps.storage, &env, 
        session_query(
                SessionQueryMsg::Derive { 
                    method: Some(ActionDerivation::Json),
                    message: msg.clone(),
                }
            )
        ).unwrap()
    ).unwrap();
    assert_eq!(json_res, r#"{"mint_token":{"minter":"jeremy","msg":{"simple":{}}}}"#);
    
}




#[test]
fn all_message_queries() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let env = mock_env();

    // Get names of all QueryMsg variants  &["get_balance", ... ]
    let msg = QueryMsg::SessionQueries(Box::new(SessionQueryMsg::AllQueries { method: None }));
    let res = query(deps.api, deps.storage, &env, msg.clone());
    assert!(res.is_ok());

    let all_queries_res : Vec<String> = from_json(&res.unwrap()).unwrap();
    assert!(QueryMsg::VARIANTS.iter().all(|v| all_queries_res.contains(&v.to_string())));
    assert!(QueryMsg::VARIANTS[1] == "re_ally_long_annoying_query");
    ////
    
    
    // Same Discriminant types
    let execute_vars = <ExecuteMsg as IntoDiscriminant>::Discriminant::VARIANTS;
    
    let query_action_vars = <<QueryMsg as QueryUsesActions>
        ::ActionMsg as IntoDiscriminant>
        ::Discriminant::VARIANTS;

    assert!(execute_vars == query_action_vars);

    let msg = session_query(SessionQueryMsg::AllActions { method: None } );
    let all_act_res : Vec<String> = from_json(query(deps.api, deps.storage, &env, msg).unwrap()).unwrap();

    assert!(execute_vars.iter().all(|v| all_act_res.contains(&v.to_string())));
    ////


    // String form of Discriminant is also equal
    let exec_strs = execute_vars.iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>();

    let action_strs = query_action_vars.iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>();
    
    assert!(exec_strs == action_strs);

    let is_camel = !action_strs.iter()
        .any(|v| v.contains(" ") || v.chars().any(|c| c.is_uppercase()));

    assert!(is_camel);
    ////


    let res = query(deps.api, deps.storage, &env, session_query(
        SessionQueryMsg::AllActions { method: Some(AllQueryDerivation::Strings)})
    ).unwrap();
    let all_act_str_res : Vec<String> = from_json(&res).unwrap();
    println!("all act res: {:?}", all_act_res);
    println!("all act str res: {:?}", all_act_str_res);

    // some are identical to the names but not all of them
    assert!(!all_act_str_res.iter().all(|v| all_act_res.contains(&v.to_string())));

    let name_freeze = all_act_res[3].clone();
    let str_freeze = all_act_str_res[3].clone();

    assert!(name_freeze != str_freeze);
    println!("name_freeze: {:?}", name_freeze);
    assert!(name_freeze.as_str() == "freeze");
    assert!(str_freeze.as_str() == "freeeeeze");


}
