use cosmwasm_schema::cw_serde;

use cw_storage_plus::Item;
use cosmwasm_std::{testing::{mock_dependencies, mock_env, mock_info}, BankMsg, CosmosMsg};
use smart_account_auth::{Credential, CredentialData};
use strum::{IntoEnumIterator, VariantArray, VariantNames};
use strum_macros::{Display, EnumDiscriminants, EnumIter, EnumString, VariantNames};

use smart_account_auth::types::expiration::Expiration;


#[cw_serde]
#[derive(Display, VariantNames, EnumString, EnumDiscriminants, EnumIter)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(strum(serialize_all = "snake_case"))]
#[strum_discriminants(derive(strum_macros::VariantArray))]
pub enum ExecuteMsg {

    #[strum(to_string = "execute: {{ msgs: Vec<CosmosMsg> }}")]
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



#[cw_serde]
pub struct ExecuteSession {
    pub owner: String,
    pub msg: ExecuteMsg
}


//#[cw_serde]
#[cw_serde]
pub enum Authority {
    Address(String),
    Credential(Credential),
}

//#[cw_serde]
#[cw_serde]
pub enum AllowedActions {
    Current(),
    Specific(Vec<String>),
    All(),
}


#[cw_serde]
pub struct SessionKey {
    pub authority   : Authority,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration
}



pub static SESSION_KEYS : Item<SessionKey> = Item::new("saa_keys");



#[test]
fn test_execute_msg() {
    let variants = ExecuteMsgDiscriminants::VARIANTS;
    println!("Variants: {:?}", variants);
    let variant_names = ExecuteMsg::VARIANTS;
    println!("Variant names: {:?}", variant_names);
    for msg in ExecuteMsg::iter() {
        println!("Msg: {:?}", msg);
    }

    let msg = ExecuteMsg::Execute { 
        msgs: vec![BankMsg::Send { to_address: "foo".into(), amount: vec![] }.into()] 
    };

    println!("Msg: {:?}", msg);
    println!("Msg: {:?}", msg.to_string());
    assert!(false);
}




#[test]
fn session_key_simple_flow() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;
    let env = mock_env();
    let alice = mock_info("alice", &[]);
    let bob = mock_info("bob", &[]);

    let actions = ExecuteMsg::VARIANTS
                .into_iter()
                .filter(|n| n.contains("token"))
                .map(|n| n.to_string())
                .collect::<Vec<String>>();

    println!("Actions: {:?}", actions);

    assert_eq!(actions.len(), 2);
    assert_eq!(actions, vec![
        String::from("mint_token"), 
        String::from("transfer_token")
    ]);

    
    let key = SessionKey {
        authority: Authority::Address(bob.sender.to_string()),
        actions: AllowedActions::Specific(actions),
        expiration: Expiration::AtHeight(env.block.height + 100),
    };

    SESSION_KEYS.save(storage, &key).unwrap();
    /* .update(&mut storage, alice.sender.to_string(), |keys| {
        let mut keys = keys.unwrap_or_default();
        keys.push(key.clone());
        Ok::<Vec<SessionKey>, AuthError>(keys)
    }).unwrap();

     */
    ////////////////

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

    let msg = execute_session.msg.to_string();
    println!("Msg: {:?}", msg);

    if let AllowedActions::Specific(actions) = &key.actions {
        if !actions.contains(&msg) {
            panic!("Action not allowed");
        }
    } else {
        panic!("Invalid actions");
    }




}