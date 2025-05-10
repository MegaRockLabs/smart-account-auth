#[allow(unused_imports, unused_variables, dead_code)]

use std::{env, ops::{Add, Deref}};

use cosmwasm_std::{ensure, testing::{message_info, mock_dependencies, mock_env}, Addr, Response, StdError, SubMsg, Uint128};
use cw_storage_plus::Map;
use saa_common::from_json;
use smart_account_auth::{messages::{Action, AllowedActions, CreateSession, CreateSessionFromMsg, DerivationMethod, MessageOption, MsgDataToSign, RevokeKeyMsg, Session, SessionInfo, WithSessionMsg}, utils::construct_credential, CredentialInfo, CredentialName};

use crate::{types::{BankMsg, Coin, CosmosMsg, ExecuteMsg, StakingMsg}, vars::session_info};

pub static SESSION_KEYS: Map<String, Session> = Map::new("saa_keys");

const ADMIN : &str = "alice";


pub fn save_session(
    storage: &mut dyn cosmwasm_std::Storage,
    key: String,
    mut session: Session,
) -> Result<(), StdError> {
    if let Ok(loaded) = load_session_key(storage, key.clone()) {
        session.nonce = loaded.nonce;
    }
    SESSION_KEYS.save(storage, key, &session)?;
    Ok(())
}


pub fn load_session_key(
    storage: &dyn cosmwasm_std::Storage,
    key: String
) -> Result<Session, cosmwasm_std::StdError> {
    SESSION_KEYS.load(storage, key)
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
            save_session(storage,  key.clone(), session)?;
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
            let key = &msg.session_key;
            if let Ok(loaded) = load_session_key(storage, key.clone()) {
                ensure!(
                    loaded.granter.unwrap_or(ADMIN.to_string()) == info.sender.to_string(), 
                    StdError::generic_err("Only owner can revoke the session key")
                );
                SESSION_KEYS.remove(storage, key.clone());
                Ok(Response::default()
                    .add_attribute("status", "session revoked")
                    .add_attribute("key", key.as_str())
                )
            } else {
                Ok(Response::default()
                    .add_attribute("status", "nothing to revoke")
                )
            }            
        },
        
        _ => {
            if info.sender.as_str() == ADMIN {
                return execute_logic(api, storage, env, info, msg);
            }
            Err(StdError::generic_err("Unauthorized to call directly"))
        }
        
    }


}


pub fn execute_logic(
    _api : &dyn cosmwasm_std::Api,
    _storage: &mut dyn cosmwasm_std::Storage,
    _env: cosmwasm_std::Env,
    _info: cosmwasm_std::MessageInfo,
    msg: ExecuteMsg,
) -> Result<cosmwasm_std::Response, cosmwasm_std::StdError> {
    
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

    let alice = Addr::unchecked("alice");
    let alice_info = message_info(&alice, &vec![]);

    let bob = Addr::unchecked("bob");
    let bob_info = message_info(&bob, &vec![]);

    let eve = Addr::unchecked("eve");
    let eve_info = message_info(&eve, &vec![]);


    // Alice can call messages directly
    assert!(execute(deps.api, deps.storage, env.clone(), alice_info.clone(), ExecuteMsg::Purge {}).is_ok());

    // Other addresses can't
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::Purge {}).is_err());
    assert!(execute(deps.api, deps.storage, env.clone(), eve_info.clone(), ExecuteMsg::Purge {}).is_err());


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


    let msg = ExecuteMsg::CreateSession(session.clone());

    // Calling smart contract here finally
    let res = execute(deps.api, deps.storage, env.clone(), alice_info.clone(), msg).unwrap();

    let found_key = res.attributes
        .into_iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .value;

    // contract set alice as granter, without it keys don't match
    let no_alice = session.to_session(&env).unwrap().key();
    assert!(found_key != no_alice);

    // if we set it we can predict what the key value is going to be to send multiple messages in a batch
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



    // This is allowed message but Bob can't call it directly
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::Purge {}).is_err());

    // He needs to always wrap it using WithSessionKey wrapper  and then it works
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg {
        message: MessageOption::Native(Box::new(ExecuteMsg::Purge {  } )),
        session_key: found_key.clone(),
    })).is_ok());


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
   



#[test]
fn from_message_and_revoking() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let env = mock_env();

    let alice = Addr::unchecked("alice");
    let alice_info = message_info(&alice, &vec![]);

    let bob = Addr::unchecked("bob");
    let bob_info = message_info(&bob, &vec![]);

    let eve = Addr::unchecked("eve");
    let eve_info = message_info(&eve, &vec![]);


    let msg = ExecuteMsg::Execute { msgs: vec![CosmosMsg::Simple {}] };
    
    let from_msg = ExecuteMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: Box::new(msg.clone()),
        derivation_method: Some(DerivationMethod::Json),
        session_info: session_info(),
    });

    let res = execute(deps.api, deps.storage, env.clone(), alice_info.clone(), from_msg.clone()).unwrap();
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

    
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg2.clone())),  
        session_key: key.clone(), 
    })).is_err());

    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg3.clone())),  
        session_key: key.clone(), 
    })).is_err());

    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg4.clone())), 
        session_key: key.clone(), 
    })).is_err());


    // the identical message goes through
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: key.clone(), 
    })).is_ok());

    
    // Alice can try creating another session key for Bob without changing anything
    let from_msg = ExecuteMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: Box::new(msg.clone()),
        derivation_method: Some(DerivationMethod::Json),
        session_info: session_info(),
    });

    let res = execute(deps.api, deps.storage, env.clone(), alice_info.clone(), from_msg.clone()).unwrap();
    let new_key = res.attributes
        .iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .clone()
        .value;

    // If params didn't change the key will be identical. However you can use this to override the expiration or creation date
    assert_eq!(key, new_key);


    // Not let's create another key where actions are detived usoing the message name
    let from_msg = ExecuteMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: Box::new(msg.clone()),
        derivation_method: None,
        session_info: session_info(),
    });

    
    let res = execute(deps.api, deps.storage, env.clone(), alice_info.clone(), from_msg.clone()).unwrap();
    let exec_name_key = res.attributes
        .iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .clone()
        .value;

    // Action list is different so the key should be different
    assert!(key != exec_name_key);



    // Bob can still use the old key
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: key.clone(), 
    })).is_ok());



    // But now with the second he can do any execute message he could do before
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg2.clone())), 
        session_key: exec_name_key.clone(), 
    })).is_ok());


    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg3.clone())), 
        session_key: exec_name_key.clone(), 
    })).is_ok());


    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg4.clone())), 
        session_key: exec_name_key.clone(), 
    })).unwrap();
    
    let msg_len = res.attributes
        .iter()
        .find(|attr| attr.key.contains("msg_len"))
        .unwrap()
        .clone()
        .value;

    assert_eq!(msg_len, "5");
    


    // Let's revoke the first key now
    let revoke_msg = ExecuteMsg::RevokeSession(RevokeKeyMsg {
        session_key: key.clone(),
    });

    
    // Bob can't revoke it
    assert!(execute(deps.api, deps.storage, env.clone(), bob_info.clone(), revoke_msg.clone()).is_err());

    // Alice can 
    let res = execute(deps.api, deps.storage, env.clone(), alice_info.clone(), ExecuteMsg::RevokeSession(RevokeKeyMsg {
        session_key: key.clone(),
    })).unwrap();


    let status_ok = res.attributes.iter().any(|attr| attr.key.contains("status") && attr.value.contains("revoked"));
    assert!(status_ok);


    // Bob can't use the old key anymore
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: key.clone(), 
    }));
    assert!(res.is_err());


    // Can still use the latest 
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: exec_name_key.clone(), 
    }));


    assert!(res.is_ok());



    // Let's create a key for Eve with identical allowed actions
    let from_msg = ExecuteMsg::CreateSessionFromMsg(CreateSessionFromMsg {
        message: Box::new(msg.clone()),
        derivation_method: None,
        session_info: SessionInfo { 
            grantee: (eve.to_string(), CredentialInfo { name: CredentialName::Native, hrp: None, extension: None}), 
            granter: None, 
            expiration: None
        },
    });

    
    let res = execute(deps.api, deps.storage, env.clone(), alice_info.clone(), from_msg.clone()).unwrap();
    let eve_key = res.attributes
        .iter()
        .find(|attr| attr.key.contains("key"))
        .unwrap()
        .clone()
        .value;



    // Eve's key is different from Bob and they can't use each other keys
    assert!(eve_key != exec_name_key);

    // Bob can't use Eve's key
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: eve_key.clone(), 
    }));
    assert!(res.is_err());


    // Eve can't use Bob's key
    let res = execute(deps.api, deps.storage, env.clone(), eve_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: exec_name_key.clone(), 
    }));
    assert!(res.is_err());


    // Bob can use his own key
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: exec_name_key.clone(), 
    }));
    assert!(res.is_ok());


    // Eve can use her own key
    let res = execute(deps.api, deps.storage, env.clone(), eve_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: eve_key.clone(), 
    }));
    assert!(res.is_ok());



    // Let's revoke Bob's key again
    let revoke_msg = ExecuteMsg::RevokeSession(RevokeKeyMsg {
        session_key: exec_name_key.clone(),
    });
    execute(deps.api, deps.storage, env.clone(), alice_info.clone(), revoke_msg).unwrap();


    // Bob can't use any of his keys anymore
    let res = execute(deps.api, deps.storage, env.clone(), bob_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: exec_name_key.clone(), 
    }));
    assert!(res.is_err());



    // Eve still can use hers
    let res = execute(deps.api, deps.storage, env.clone(), eve_info.clone(), ExecuteMsg::WithSessionKey(WithSessionMsg { 
        message: MessageOption::Native(Box::new(msg.clone())), 
        session_key: eve_key.clone(), 
    }));
    assert!(res.is_ok());


}
    

