#[allow(unused_imports, unused_variables, dead_code)]

use std::{env, ops::{Add, Deref}};

use cosmwasm_std::{ensure, testing::{message_info, mock_dependencies, mock_env}, Addr, Response, StdError, SubMsg};
use cw_storage_plus::Map;
use saa_common::from_json;
use smart_account_auth::{messages::{Action, AllowedActions, CreateSession, MessageOption, MsgDataToSign, Session, SessionInfo, WithSessionMsg}, storage::{credential_from_payload, load_credential}, utils::construct_credential, verify_caller, verify_signed, CredentialName};

use crate::{types::{CosmosMsg, ExecuteMsg}, vars::session_info};

pub static SESSION_KEYS: Map<String, Session> = Map::new("saa_keys");

const ADMIN : &str = "alice";


pub fn save_session(
    storage: &mut dyn cosmwasm_std::Storage,
    key: String,
    session: Session,
) -> Result<(), StdError> {
    SESSION_KEYS.save(storage, key, &session)?;
    Ok(())
}

pub fn load_session_key(
    storage: &dyn cosmwasm_std::Storage,
    id: String
) -> Result<Session, cosmwasm_std::StdError> {
    SESSION_KEYS.load(storage, id)
}


pub fn execute(
    api : &dyn cosmwasm_std::Api,
    storage: &mut dyn cosmwasm_std::Storage,
    env: cosmwasm_std::Env,
    mut info: cosmwasm_std::MessageInfo,
    msg: ExecuteMsg,
) -> Result<cosmwasm_std::Response, cosmwasm_std::StdError> {
    
    match msg {
        ExecuteMsg::CreateSession(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(info.sender.to_string());
            let session = create.to_session(&env).unwrap();
            let key = session.key();
            save_session(storage,  key.clone(), session)?;
            Ok(Response::default().add_attribute("key", key))
        },

        ExecuteMsg::CreateSessionFromMsg(
            mut create
        ) => {
             // set sender as granter
            create.session_info.granter = Some(info.sender.to_string());
            let session = create.to_session(&env).unwrap();
            let key = session.key();
            save_session(storage,  key.clone(), session);
            let res = execute_logic(api, storage, env, info, create.message.deref().to_owned())?;
            Ok(res.add_attribute("key", key))
        },

        ExecuteMsg::WithSessionKey(with_msg) => {

            let key = &with_msg.session_key;
            let mut session = load_session_key(storage, key.clone())?;
            let (id, cred_info) = session.grantee.clone();

            let mut res = Response::new();

            if session.expiration.is_expired(&env.block) {
                SESSION_KEYS.remove(storage, key.clone());
                res = Response::new()
                    .add_attribute("status", "session expired")
                    .add_attribute("key", key.as_str());
                return Ok(res);
            }


            let msgs = match with_msg.message {
                MessageOption::Native(execute) => {
                    ensure!(cred_info.name == CredentialName::Native, StdError::generic_err("This key wasn't for a native address"));
                    ensure!(id == info.sender.to_string(), StdError::generic_err("This key wasn't for this address"));
                    vec![execute.deref().clone()]

                },
                MessageOption::Signed(msg) => {
                    
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

                    let to_sign : MsgDataToSign<ExecuteMsg> = from_json(msg.data)?;
                    ensure!(env.block.chain_id == to_sign.chain_id, StdError::generic_err("Chain ID mismatch"));
                    ensure!(env.contract.address.to_string() == to_sign.contract_address, StdError::generic_err("Contract address mismatch"));
                    ensure!(session.nonce.to_string() == to_sign.nonce, StdError::generic_err("Nonce mismatch"));

                    if cred.is_cosmos_derivable() {
                        let addr = cred.cosmos_address(api)
                            .map_err(|_| StdError::generic_err("Invalid address"))?;
                        info.sender = addr;
                    }

                    session.nonce += 1;
                    save_session(storage, key.clone(), session.clone())?;

                    to_sign.messages
                }
            };


            let mut sub_msgs: Vec<SubMsg> = Vec::with_capacity(msgs.len() + 2);

            for msg in msgs {

                if !session.actions.is_message_allowed(&msg) {
                    return Err(StdError::generic_err("Message not allowed"));
                } 

                let msg_res = execute_logic(api, storage, env.clone(), info.clone(), msg)?;
                sub_msgs.extend(msg_res.messages.clone());


                res = res.add_events(msg_res.events)
                        .add_attributes(msg_res.attributes);

                if res.data.is_none() && msg_res.data.is_some() {
                    res = res.set_data(msg_res.data.unwrap());
                }
            }
            res = res
                .add_submessages(sub_msgs)
                .add_attribute("nonce", session.nonce.to_string());
            Ok(res)
        },

        ExecuteMsg::RevokeSession(msg) => {
            let key = msg.session_key;
            SESSION_KEYS.remove(storage, key.clone());
            Ok(Response::default()
                .add_attribute("status", "session revoked")
                .add_attribute("key", key.as_str())
            )
        },

        msg => execute_logic(api, storage, env, info, msg)
        
    }


}


pub fn execute_logic(
    _api : &dyn cosmwasm_std::Api,
    _storage: &mut dyn cosmwasm_std::Storage,
    env: cosmwasm_std::Env,
    info: cosmwasm_std::MessageInfo,
    msg: ExecuteMsg,
) -> Result<cosmwasm_std::Response, cosmwasm_std::StdError> {
    
    match msg {

        ExecuteMsg::MintToken { minter, msg } => {
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

        _ => unreachable!("CreateSession should be handled in execute"),
    }
}






#[test]
fn simple_contract_flow() {

    let mut mocks = mock_dependencies();
    let mut deps = mocks.as_mut();
    let mut env = mock_env();

    let alice = Addr::unchecked("alice");
    let alice_info = message_info(&alice, &vec![]);

    let bob = Addr::unchecked("bob");
    let bob_info = message_info(&bob, &vec![]);

    let eve = Addr::unchecked("eve");
    let eve_info = message_info(&eve, &vec![]);


    let allowed_actions = AllowedActions::Include(vec![
        Action::with_str(ExecuteMsg::MintToken { 
            minter: "minter_contract".into(), 
            msg: None 
        }), 
        Action::with_str(ExecuteMsg::Execute { msgs: vec![CosmosMsg::Simple {}] }), 
        Action::with_str(ExecuteMsg::Purge { })
    ]);

    // set to grantee to bob
    let mut session = CreateSession {
        allowed_actions: allowed_actions.clone(),
        session_info: session_info(),
    };
    session.session_info.expiration = Some(saa_common::Expiration::AtHeight(env.block.height + 100));


    let msg = ExecuteMsg::CreateSession(session.clone());


    // Calling smart contract here
    let res = execute(deps.api, deps.storage, env.clone(), alice_info.clone(), msg).unwrap();

    let found_key = res.attributes
        .into_iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .value;


    let no_alice = session.to_session(&env).unwrap().key();
    assert!(found_key != no_alice);

    session.session_info.granter = Some(alice_info.sender.to_string());
    let expected = session.to_session(&env).unwrap().key();
    assert_eq!(found_key, expected);



    // Now Bob should be able to use the session key

    let exec_msg = ExecuteMsg::WithSessionKey(WithSessionMsg {
        message: MessageOption::Native(Box::new(ExecuteMsg::MintToken { 
            minter: "minter_contract".into(), 
            msg: None 
        })),
        session_key: found_key.clone(),
    });

    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), exec_msg.clone()).unwrap();

    // All good
    let minted = res.attributes
        .into_iter()
        .any(|attr| attr.key.contains("status") && attr.value.contains("minted"));

    assert!(minted);    


    // Eve can't do it even with the same message
    let eve_res = execute(deps.api, deps.storage, env.clone(), eve_info.clone(), exec_msg.clone());
    assert_eq!(eve_res.unwrap_err().to_string(), "Generic error: This key wasn't for this address".to_string());


    // Bob can't do it with minter address change even a tiny bit
    let exec_msg = ExecuteMsg::WithSessionKey(WithSessionMsg {
        message: MessageOption::Native(Box::new(ExecuteMsg::MintToken { 
            minter: "minter_contractt".into(), 
            msg: None 
        })),
        session_key: found_key.clone(),
    });
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), exec_msg.clone());
    assert_eq!(res.unwrap_err().to_string(), "Generic error: Message not allowed".to_string());



    // Bob can do ExecuteMsg::Execute  that is not identical to one in the allowed list
    // cause it was specified to use name for derivation
    let exec_msg = ExecuteMsg::WithSessionKey(WithSessionMsg {
        message: MessageOption::Native(Box::new(ExecuteMsg::Execute { msgs: vec![] })),
        session_key: found_key.clone(),
    });
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), exec_msg.clone());
    assert!(res.is_ok());



    // Bob can't do other messages
    let exec_msg = ExecuteMsg::WithSessionKey(WithSessionMsg {
        message: MessageOption::Native(Box::new(ExecuteMsg::Freeze {  } )),
        session_key: found_key.clone(),
    });
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), exec_msg.clone());
    assert!(res.is_err());



    // later when time passed out seesion key get expired and deleted
    env.block.height += 101;


    // Bob can't use the old valid message anymore
    let exec_msg = ExecuteMsg::WithSessionKey(WithSessionMsg {
        message: MessageOption::Native(Box::new(ExecuteMsg::MintToken { 
            minter: "minter_contract".into(), 
            msg: None 
        })),
        session_key: found_key.clone(),
    });

    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), exec_msg.clone()).unwrap();

    let status = res.attributes
        .iter()
        .find(|attr| attr.key.contains("status"))
        .unwrap().clone()
        .value;


    assert_eq!(status, "session expired");

    let minter_event_exist = res.attributes
        .into_iter()
        .any(|attr| attr.key.contains("minter"));


    assert!(!minter_event_exist);
}
   