
use cosmwasm_std::{ensure, testing::{message_info, mock_dependencies, mock_env}, Addr, Response, StdError, Uint128};
use saa_common::{from_json, AuthError, SessionError};
use serde::de::DeserializeOwned;
use smart_account_auth::{
    messages::{
        Action, ActionMsg, AllowedActions, CreateSession, CreateSessionFromMsg, DerivationMethod, MsgDataToSign, RevokeKeyMsg, Session, SessionActionMsg, SessionActionsMatch, SessionInfo
    }, 
    storage::session::{load_session, revoke_session, save_session}, 
    utils::construct_credential, CredentialInfo, CredentialName
};

use crate::{types::{BankMsg, Coin, CosmosMsg, ExecuteMsg, StakingMsg}, vars::{session_info, with_key_msg}};


const ADMIN : &str = "alice";



pub fn handle_session<M>(
    api : &dyn cosmwasm_std::Api,
    storage: &mut dyn cosmwasm_std::Storage,
    env: &cosmwasm_std::Env,
    info: &cosmwasm_std::MessageInfo,
    msg: M,
) -> Result<(Option<Session>, Vec<M>), AuthError> 
    where M : DeserializeOwned + SessionActionsMatch,
{
    let session_msg = match msg.match_actions() {
        Some(msg) => msg,
        None => return Ok((None, vec![msg.clone()])),
    };
       
    match session_msg {
        SessionActionMsg::CreateSession(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(info.sender.to_string());
            let session = create.to_session(&env).unwrap();
            let key = session.key();
            save_session(storage,  key.clone(), session.clone())?;
            Ok((Some(session), vec![]))
        },

        SessionActionMsg::CreateSessionFromMsg(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(info.sender.to_string());
            let session = create.to_session(&env).unwrap();
            let key = session.key();
            save_session(storage,  key.clone(), session.clone())?;
            Ok((Some(session), vec![create.message.clone()]))
        },

        SessionActionMsg::WithSessionKey(with_msg) => {

            let key = &with_msg.session_key;
            let mut session = load_session(storage, key.clone())?;
            let (id, cred_info) = session.grantee.clone();

            if session.expiration.is_expired(&env.block) {
                revoke_session(storage, key.clone());
                return Err(SessionError::Expired.into())
            }

            let msgs : Vec<M>  = match with_msg.message {
                ActionMsg::Signed(msg) => {
                    
                    let hrp = msg.payload
                        .as_ref().map(|p| p.hrp.clone())
                        .flatten();

                    let stored_ext = cred_info.extension.clone();

                    let passed_ext = msg.payload
                        .as_ref().map(|p| p.extension.clone())
                        .flatten();

                    let cred = construct_credential(
                        id, 
                        cred_info.name, 
                        msg.data.clone(), 
                        msg.signature, 
                        hrp, 
                        stored_ext, 
                        passed_ext
                    ).map_err(|_| StdError::generic_err("Invalid credential"))?;

                    cred.verify_cosmwasm(api)
                        .map_err(|_| StdError::generic_err("Invalid signature"))?;

                    let to_sign : MsgDataToSign<M> = from_json(msg.data)?;
                    ensure!(env.block.chain_id == to_sign.chain_id, StdError::generic_err("Chain ID mismatch"));
                    ensure!(env.contract.address.to_string() == to_sign.contract_address, StdError::generic_err("Contract address mismatch"));
                    ensure!(session.nonce.to_string() == to_sign.nonce, StdError::generic_err("Nonce mismatch"));

                    if cred.is_cosmos_derivable() {
                        let _addr = cred.cosmos_address(api)
                            .map_err(|_| StdError::generic_err("Invalid address"))?;
                        //info.sender = addr;
                    }
                    session.nonce += 1;
                    save_session(storage, key.clone(), session.clone())?;
                    to_sign.messages
                }
                ActionMsg::Native(execute) => {
                    ensure!(cred_info.name == CredentialName::Native, StdError::generic_err("This key wasn't for a native address"));
                    ensure!(id == info.sender.to_string(), StdError::generic_err("This key wasn't for this address"));
                    vec![execute.clone()]
                },
            };
            ensure!(!msgs.is_empty(), SessionError::EmptyPassedActions);
            ensure!(msgs.iter().all(|m| session.actions.is_message_allowed(m)), SessionError::NotAllowedAction);
            Ok((Some(session), msgs))
        },

        SessionActionMsg::RevokeSession(msg) => {
            let key = &msg.session_key;
            if let Ok(loaded) = load_session(storage, key.clone()) {
                ensure!(
                    loaded.granter == info.sender.to_string(), 
                    StdError::generic_err("Only owner can revoke the session key")
                );
                revoke_session(storage, key.clone());
                Ok((None, vec![]))
            } else {
                return Err(SessionError::Expired.into())
            }            
        },
    }
    
}




pub fn execute(
    api : &dyn cosmwasm_std::Api,
    storage: &mut dyn cosmwasm_std::Storage,
    env: &cosmwasm_std::Env,
    info: &cosmwasm_std::MessageInfo,
    msg: ExecuteMsg,
) -> Result<cosmwasm_std::Response, AuthError> {

    let (session, inner_msgs) = handle_session(
        api, 
        storage, 
        env, 
        info, 
        msg
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

        (1, None) => {
            ensure!(info.sender.as_str() == ADMIN, StdError::generic_err("Unauthorized to call directly"));
            execute_logic(api, storage, env, info, inner_msgs[0].clone())
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






#[test]
fn simple_contract_flow() {

    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let mut env = mock_env();

    let alice_addr = Addr::unchecked("alice");
    let alice = message_info(&alice_addr, &vec![]);

    let bob_addr = Addr::unchecked("bob");
    let bob = message_info(&bob_addr, &vec![]);

    let eve_addr = Addr::unchecked("eve");
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
    session.session_info.expiration = Some(saa_common::Expiration::AtHeight(env.block.height + 100));


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
    assert_eq!(eve_res.unwrap_err().to_string(), "Generic error: This key wasn't for this address".to_string());



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
    let env = mock_env();

    let alice_addr = Addr::unchecked("alice");
    let alice = message_info(&alice_addr, &vec![]);
    let bob_addr = Addr::unchecked("bob");
    let bob = message_info(&bob_addr, &vec![]);
    let eve_addr = Addr::unchecked("eve");
    let eve = message_info(&eve_addr, &vec![]);


    let msg = ExecuteMsg::Execute { msgs: vec![CosmosMsg::Simple {}] };

    let alice = &alice;
    let env = &env;

    let from_msg = ExecuteMsg::SessionActions(Box::new(SessionActionMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: msg.clone(),
        derivation_method: Some(DerivationMethod::Json),
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
    let msg3 = ExecuteMsg::Execute { msgs: vec![CosmosMsg::Bank(BankMsg::Send {to_address: "eve".to_string(), amount: vec![]})]};
    let msg4 = ExecuteMsg::Execute { msgs: vec![
        CosmosMsg::Simple { }, 
        CosmosMsg::Simple { }, 
        CosmosMsg::Staking(StakingMsg::Delegate { 
            validator: "POSERS".to_string(), 
            amount: Coin { denom: "atom".to_string(), amount: Uint128::from(1_000_000_000u128) } 
        }),
        CosmosMsg::Bank(BankMsg::Send {
            to_address: "eve".to_string(), 
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
        derivation_method: Some(DerivationMethod::Json),
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
        derivation_method: None,
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
    let revoke_msg = ExecuteMsg::SessionActions(Box::new(SessionActionMsg::RevokeSession(RevokeKeyMsg {
        session_key: key.to_string(),
    })));

    
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
            derivation_method: None,
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
    

