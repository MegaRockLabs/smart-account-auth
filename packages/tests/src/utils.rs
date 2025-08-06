use cosmwasm_std::testing::{message_info, mock_dependencies, MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{Empty, MessageInfo, OwnedDeps};
use cosmwasm_std::{testing::mock_env, Addr, Env};
use saa_common::Binary;
use smart_account_auth::{ 
    Credential, CosmosArbitrary, EthPersonalSign, PasskeyCredential,
    types::ClientData, 
};

use smart_account_auth::utils::passkey::base64_to_url;


pub const SIGN_CHAIN_ID : &str = "elgafar-1";
pub const SIGN_CONTRACT_ADDRESS : &str = "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn";
pub const SIGN_MESSAGE_TEXT : &str = "Testing smart-account-auth library";
pub const SIGN_NONCE : u64 = 0;


// pub const SIGN_MESSAGE_PLAIN : &str = r#"{"chain_id":"elgafar-1","contract_address":"stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn","messages":["Testing smart-account-auth library"],"nonce":"0"}"#;
pub const SIGN_MESSAGE_BASE64 : &str = "eyJjaGFpbl9pZCI6ImVsZ2FmYXItMSIsImNvbnRyYWN0X2FkZHJlc3MiOiJzdGFyczF3Z2VzejVqcngzdXZ0MjlhOWF3a2FmeTRwMDZydXR4djJ4ZG5xcGVyZGU0dG16eDRuMnlxOTVtdW1uIiwibWVzc2FnZXMiOlsiVGVzdGluZyBzbWFydC1hY2NvdW50LWF1dGggbGlicmFyeSJdLCJub25jZSI6IjAifQ==";



pub const ALICE_ADDR : &str = "stars190vqdjtlpcq27xslcveglfmr4ynfwg7gmw86cnun4acakxrdd6gqg074pt";
// pub const BOB_ADDR : &str = "stars1sxmr0k8u6trd5c6eu6trzyapzux7090ykujmsng7pdx0m8k93n5skp3k29";
// pub const EVE_ADDR : &str = "stars1s5nz4hm52x9mkux8ew2v6c2emytxnedgrm03al4a2sl2m0dflg4sfppadm";



pub fn get_eth_personal() -> EthPersonalSign {
    EthPersonalSign {
        signer : get_eth_signer(),
        signature: Binary::from_base64("ohEtmdTyusVQbidIhRxi7SPR8grzz99OW98gcqU2ziQ2WYL+UOVbQC8l1XPHWjg2axMAMep0ual3kl2zlnawcxs=").unwrap(),
        message: Binary::from_base64(SIGN_MESSAGE_BASE64).unwrap()

    }
}

    

pub fn get_cosmos_arbitrary() -> CosmosArbitrary {
    CosmosArbitrary {
        pubkey: Binary::from_base64("A2LjUH7Q0gi7+Wi0/MnXMZqN8slsz7iHMfTWp8xUXspH").unwrap(),
        message: Binary::from_base64(SIGN_MESSAGE_BASE64).unwrap(),
        signature: Binary::from_base64("jfoaUrJHF17xrapXWfu2KPDd2jcDI/02Rbv9PI1PWx5ugxHGVv99V1Scu7FZVKYVqrL9tCt4sX3hFX/7ul4dcg==").unwrap(),
        address: get_star_address(),
    }
}


pub fn get_eth_signer() -> String {
    "0x".to_owned() + &hex::encode(
        [172, 3, 4, 141, 166, 6, 94, 88, 77, 82, 0, 126, 34, 198, 145, 116, 205, 242, 185, 26]
    )
}

pub fn get_star_address() -> String {
     String::from_utf8([
        115, 116, 97, 114, 115, 49, 118, 56, 53, 109, 52, 115, 120, 110, 110, 100, 119, 109, 115, 119,
        116, 100, 56, 106, 114, 122, 51, 99, 100, 50, 109, 56, 117, 56, 101, 101, 103, 113, 100, 120,
        121, 108, 117, 122]
        .to_vec()
    ).unwrap()
}


pub fn get_passkey() -> PasskeyCredential {
    PasskeyCredential { 
        id: "qA19jUJhKeCAUgQcucVp7RYRosqUv_dO4DTxxhobN0w".to_string(),
        authenticator_data: Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==").unwrap(), 
        signature: Binary::from_base64("5uM7Ut/syEjDrTS9r1iSAvHUD/ib0y0ckDuTueqejZqIUlo3YI1mx69nNCI1k5Yy1k4G/5BYMfoidput7nhnhQ==").unwrap(), 
        pubkey: Some(Binary::from_base64("BDh2fdKVC0AAoRvIT5c7Z0T2fOfal3B74EE4NHAH/eBawRMwRL9pt1OQllwKvhtaYFdp/gyVgUwqSRJ1wmIMvSY=").unwrap()), 
        client_data: ClientData::new( base64_to_url(SIGN_MESSAGE_BASE64), "http://localhost:5173", false, None), 
        user_handle: None
    }
}


pub fn base_credentials() -> Vec<Credential> {
    vec![
        Credential::Passkey(get_passkey()),
        Credential::EthPersonalSign(get_eth_personal()),
        Credential::CosmosArbitrary(get_cosmos_arbitrary())
    ]
}


pub fn get_mock_deps() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>  {
    let mut deps = mock_dependencies();
    deps.api = MockApi::default().with_prefix("stars");
    deps
}



pub fn get_mock_env() -> Env {
    let mut env = mock_env();
    env.block.chain_id = SIGN_CHAIN_ID.to_string();
    env.contract.address = Addr::unchecked(SIGN_CONTRACT_ADDRESS);
    env
}


pub fn alice_info() -> MessageInfo {
    message_info(&Addr::unchecked(ALICE_ADDR), &[])
}
