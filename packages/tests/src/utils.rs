
#![allow(dead_code)]
use cosmwasm_std::{testing::mock_env, Addr, Env};
use saa_common::Binary;
use cw_auths::saa_types::{ 
    Credential, CredentialData, CredentialInfo, CredentialName, SessionInfo, 
    CosmosArbitrary, EthPersonalSign, PasskeyCredential,
    types::ClientData, 
};
use cw_auths::{
    ActionMsg, SessionActionMsg, WithSessionMsg,
    SessionQueryMsg
};

use smart_account_auth::utils::passkey::base64_to_url;
use crate::types::{ExecuteMsg, QueryMsg};


pub const SIGN_CHAIN_ID : &str = "elgafar-1";
pub const SIGN_CONTRACT_ADDRESS : &str = "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn";
pub const SIGN_MESSAGE_TEXT : &str = "Testing smart-account-auth library";
pub const SIGN_NONCE : &str = "0";

pub const SIGN_MESSAGE_PLAIN : &str = r#"{"chain_id":"elgafar-1","contract_address":"stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn","messages":["Testing smart-account-auth library"],"nonce":"0"}"#;
pub const SIGN_MESSAGE_BASE64 : &str = "eyJjaGFpbl9pZCI6ImVsZ2FmYXItMSIsImNvbnRyYWN0X2FkZHJlc3MiOiJzdGFyczF3Z2VzejVqcngzdXZ0MjlhOWF3a2FmeTRwMDZydXR4djJ4ZG5xcGVyZGU0dG16eDRuMnlxOTVtdW1uIiwibWVzc2FnZXMiOlsiVGVzdGluZyBzbWFydC1hY2NvdW50LWF1dGggbGlicmFyeSJdLCJub25jZSI6IjAifQ==";


pub const ALICE_ADDR : &str = "cosmwasm190vqdjtlpcq27xslcveglfmr4ynfwg7gmw86cnun4acakxrdd6gqvdcx9h";
pub const BOB_ADDR : &str = "cosmwasm1sxmr0k8u6trd5c6eu6trzyapzux7090ykujmsng7pdx0m8k93n5sjrh9we";
pub const EVE_ADDR : &str = "cosmwasm1s5nz4hm52x9mkux8ew2v6c2emytxnedgrm03al4a2sl2m0dflg4sdr8wf8";

pub fn get_eth_personal() -> EthPersonalSign {
    EthPersonalSign {
        signer : "0xac03048da6065e584d52007e22c69174cdf2b91a".to_string(),
        signature: Binary::from_base64("ohEtmdTyusVQbidIhRxi7SPR8grzz99OW98gcqU2ziQ2WYL+UOVbQC8l1XPHWjg2axMAMep0ual3kl2zlnawcxs=").unwrap(),
        message: Binary::from_base64(SIGN_MESSAGE_BASE64).unwrap()

    }
}

    

pub fn get_cosmos_arbitrary() -> CosmosArbitrary {
    CosmosArbitrary {
        pubkey: Binary::from_base64("A2LjUH7Q0gi7+Wi0/MnXMZqN8slsz7iHMfTWp8xUXspH").unwrap(),
        message: Binary::from_base64(SIGN_MESSAGE_BASE64).unwrap(),
        signature: Binary::from_base64("jfoaUrJHF17xrapXWfu2KPDd2jcDI/02Rbv9PI1PWx5ugxHGVv99V1Scu7FZVKYVqrL9tCt4sX3hFX/7ul4dcg==").unwrap(),
        hrp: Some("stars".to_string()),
    }
}



pub fn get_passkey() -> PasskeyCredential {
    PasskeyCredential { 
        id: "qA19jUJhKeCAUgQcucVp7RYRosqUv_dO4DTxxhobN0w".to_string(),
        authenticator_data: Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==").unwrap(), 
        signature: Binary::from_base64("5uM7Ut/syEjDrTS9r1iSAvHUD/ib0y0ckDuTueqejZqIUlo3YI1mx69nNCI1k5Yy1k4G/5BYMfoidput7nhnhQ==").unwrap(), 
        pubkey: Some(Binary::from_base64("BDh2fdKVC0AAoRvIT5c7Z0T2fOfal3B74EE4NHAH/eBawRMwRL9pt1OQllwKvhtaYFdp/gyVgUwqSRJ1wmIMvSY=").unwrap()), 
        client_data: ClientData::new("webauthn.get", base64_to_url(SIGN_MESSAGE_BASE64), "http://localhost:5173", false, None), 
        user_handle: None
    }
}


pub fn all_credentials() -> Vec<Credential> {
    vec![
        Credential::Passkey(get_passkey()),
        Credential::EthPersonalSign(get_eth_personal()),
        Credential::CosmosArbitrary(get_cosmos_arbitrary())
    ]
}

pub fn default_cred_count() -> usize {
    all_credentials().len()
}



pub fn credential_data() -> CredentialData {
    CredentialData {
        credentials: all_credentials(),
        use_native: Some(true),
        primary_index: None,
    }
}

pub fn cred_data_only_native(caller : &str) -> CredentialData {
    CredentialData {
        credentials: vec![],
        use_native: Some(true),
        primary_index: None,
    }.with_native(caller)
}




pub fn cred_data_non_native() -> CredentialData {
    CredentialData {
        credentials: all_credentials(),
        use_native: None,
        primary_index: None,
    }
}



pub fn get_mock_env() -> Env {
    let mut env = mock_env();
    env.block.chain_id = SIGN_CHAIN_ID.to_string();
    env.contract.address = Addr::unchecked(SIGN_CONTRACT_ADDRESS);
    env
}


pub fn session_info() -> SessionInfo {
    SessionInfo {
        expiration: None,
        granter: None,
        grantee: (BOB_ADDR.to_string(), CredentialInfo {
            name: CredentialName::Native,
            hrp: None,
            extension: None
        }),
    }
}

pub fn with_key_msg(msg: ExecuteMsg, key: &String) -> ExecuteMsg {
    ExecuteMsg::SessionActions(Box::new(SessionActionMsg::WithSessionKey(WithSessionMsg {
        message: ActionMsg::Native(msg),
        session_key: key.to_string(),
    })))
}


pub fn session_query(msg: SessionQueryMsg<QueryMsg>) -> QueryMsg {
    QueryMsg::SessionQueries(Box::new(msg))
}