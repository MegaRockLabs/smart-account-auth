use std::{collections::BTreeMap, fmt::Display};

use crate::{types::ExecuteMsg, utils::{get_eth_signer, get_mock_deps, get_mock_env, SIGN_CHAIN_ID, SIGN_CONTRACT_ADDRESS, SIGN_MESSAGE_TEXT, SIGN_NONCE}};
use saa_common::{to_json_binary, to_json_string, types::exts::Eip712DomainType, AuthError, Binary, CredentialAddress, CredentialError, CredentialName, InfoExtension, ReplayError, Verifiable};
use serde::Serialize;
use serde_json::{from_value, json, Value};
use smart_account_auth::{
    types::{Eip712Domain, Eip712Message}, 
    utils::hashes::keccak256, 
    CheckOption, EthTypedData, ReplayParams, ReplayProtection
};

use smart_account_auth::utils::eth::prehash_eth_typed;


fn domain_type(n: &str, t: &str) -> Eip712DomainType {
    Eip712DomainType {
        name: n.to_string(),
        r#type: t.to_string(),
    }
}

fn cred_err(prop: &str, err: &str) -> AuthError {
    AuthError::Credential(CredentialError::InvalidProperty(
        CredentialName::EthTypedData,
        prop.to_string(),
        err.to_string()
    )) 
}



fn domain_attrs() -> Vec<Eip712DomainType> {
    vec![
        Eip712DomainType { name: "name".to_string(), r#type: "string".to_string() },
        Eip712DomainType { name: "version".to_string(), r#type: "string".to_string() },
        Eip712DomainType { name: "chainId".to_string(), r#type: "uint256".to_string() },
        Eip712DomainType { name: "verifyingContract".to_string(), r#type: "address".to_string() },
    ]
}



fn def_cred(verifying_addr: String) -> EthTypedData {
    EthTypedData {
        domain: Eip712Domain {
            name: Some("Token-Bound Accounts".to_string()),
            version: Some("1.1".to_string()),
            verifying_contract: Some(verifying_addr),
            chain_id: Some(0u64.into()),
            salt: None
        },
        types: from_value(json!({ "EIP712Domain": domain_attrs() })).unwrap(),
        primary_type: "EIP712Domain".into(),
        message_property: None,
        message: BTreeMap::new(),
        signer: get_eth_signer(),
        signature: Binary::default(),
        cache: None,
    }
}


#[test]
fn replay_eth_typed_no_text() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();

    let msgs_arg = vec![SIGN_MESSAGE_TEXT.to_string()];

    let replay_msg_hash = keccak256(
        &[
            SIGN_CHAIN_ID.as_bytes(),
            SIGN_CONTRACT_ADDRESS.as_bytes(),
            &SIGN_NONCE.to_be_bytes()
        ].concat()
    );
    println!("Replay message hash: {}", hex::encode(&replay_msg_hash));
    // let replay_address = "0x2d70c6e3bc825379881c9305495ddf2e287ee808".to_string();
    let replay_address = "0x".to_owned() + &hex::encode(&replay_msg_hash[12..]);
    println!("Replay address: {}\n", replay_address);

    let cred = EthTypedData {
        signature: Binary::from_base64(
            "fvDg5kwixVclXOnV7Bk+ANPDgRQ581Joakmum2WCBhoCniDX+rikX0sjGK1BuOAhI+ahBUSGcyADKHaQRX1apBw="
        ).unwrap(),
        ..def_cred(replay_address)

    };

    // passing field validation
    assert!(cred.validate().is_ok());
    // passing signature verification
    assert!(cred.verify(deps).is_ok());


    // passing replay check using a text from message["message"] 
    println!("Cred: {:?}", cred.protect_reply(
        &env, ReplayParams::new(SIGN_NONCE, CheckOption::Nothing)
    ));
    assert!(cred.protect_reply(
        &env, ReplayParams::new(SIGN_NONCE, CheckOption::Nothing)
    ).is_ok());

    // enforcing the messages will fail the check
    assert!(cred.protect_reply(
        &env, ReplayParams::new(SIGN_NONCE, CheckOption::Messages(msgs_arg)))
    .is_err());


    assert_eq!(
        EthTypedData { message_property: Some("test".into()), ..cred }.validate().unwrap_err(),
        cred_err("message_property", "cannot be set for EIP712Domain")
    );

}






#[test]
fn replay_eth_typed_envelope() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();


    const WRONG_MSG : &str = "random message";

    let params_msg = ReplayParams::new(SIGN_NONCE, CheckOption::Messages(
        vec![SIGN_MESSAGE_TEXT.to_string()])
    );
    let param_wrong = ReplayParams::new(SIGN_NONCE, CheckOption::Text(
        WRONG_MSG.to_string())
    );
    let params_empty = ReplayParams::new(SIGN_NONCE, CheckOption::Nothing);

    let replay_msg_hash = keccak256(
        &[
            SIGN_CHAIN_ID.as_bytes(),
            SIGN_CONTRACT_ADDRESS.as_bytes(),
            SIGN_MESSAGE_TEXT.as_bytes(),
            &SIGN_NONCE.to_be_bytes()
        ].concat()
    );
    // let replay_address = "0x0ef13906b325aba3cb700fe97a6edf86dcfee89a".to_string();
    let replay_address = "0x".to_owned() + &hex::encode(&replay_msg_hash[12..]);

    let cred = EthTypedData {
        types: from_value(json!({ 
            "EIP712Domain": domain_attrs(),
            "Envelope": [domain_type("message", "string")]
        })).unwrap(),
        primary_type: "Envelope".into(),
        message: from_value(json!({"message": SIGN_MESSAGE_TEXT})).unwrap(),
        signature: Binary::from_base64("kfeJTRwU9zdDeX13YUtcL9LTaOsHJlZRXOnC+aHglER/ORs2ggZL8lj6IjoqJeorWXcp9A+dfs9lDkgmrzp3vxw=").unwrap(),
        ..def_cred(replay_address)
    };

    // passing field validation
    assert!(cred.validate().is_ok());
    // passing signature verification
    assert!(cred.verify(deps).is_ok());

    // passing replay check with passed argument messages
    assert!(cred.protect_reply(&env, params_msg.clone()).is_ok());
    // passing replay check using a text from message["message"] 
    assert!(cred.protect_reply(&env, params_empty.clone()).is_ok());

    
    // same as default
    assert!
        (EthTypedData { message_property: Some("message".into()), ..cred.clone() }
        .protect_reply(&env, params_empty.clone()).is_ok()
    );

    // same with a list of 1 element
    assert!(
        EthTypedData { message: from_value(json!({"messages": [SIGN_MESSAGE_TEXT]})).unwrap(), ..cred.clone() }
        .protect_reply(&env, params_empty).is_ok()
    );


    // passed argument messages is used by default so it fails despite the inner signed message being correct
    assert_eq!(cred.protect_reply(&env, param_wrong).unwrap_err(), ReplayError::InvalidEnvelope);


    // if arguments are correct the inner message can be anything as long as verifying contract matched the arguments 
    assert!(
        EthTypedData { message: from_value(json!({"message": WRONG_MSG})).unwrap(), ..cred.clone() }
        .protect_reply(&env, params_msg).is_ok()
    );


    // failing validation if primary_type is not in types
    assert_eq!(
        EthTypedData { types: from_value(json!({ "EIP712Domain": domain_attrs() })).unwrap(), ..cred }
        .validate().unwrap_err(),  cred_err("primaryType", "must be in 'types'")
    );
  
    
}




#[test]
fn replay_eth_typed_custom_prop() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();

    let msgs = vec![SIGN_MESSAGE_TEXT.to_string()];
    let param_msgs = ReplayParams::new(SIGN_NONCE, CheckOption::Messages(msgs.clone()));
    let params_empty = ReplayParams::new(SIGN_NONCE, CheckOption::Nothing);

    let replay_address = "0x0ef13906b325aba3cb700fe97a6edf86dcfee89a".to_string();

    // invalid first
    let mut cred = EthTypedData {
        types: from_value(json!({ 
            "EIP712Domain": domain_attrs(),
            "Envelope": [domain_type("message", "string")] // not changed to custom yet
        })).unwrap(),
        primary_type: "Envelope".into(),
        message_property: Some("non-message".into()),
        message: from_value(json!({"message": SIGN_MESSAGE_TEXT})).unwrap(), // not changed to custom yet
        signature: Binary::from_base64(
            "h+co9hTMnZq8es+Ty7fTSCcrpeowl/2XSyW3wM4hfzhSli396qKIwGMM+i4S0M3/VwFWAsakYzgHe4F48kOkDRw="
        ).unwrap(),
        ..def_cred(replay_address)
    };

    // failing validation if message_property is set explicitly but isn't present in the signed message
    assert_eq!(cred.validate().unwrap_err(),  cred_err("message_property", "must be in 'message'"));
    cred.message = from_value(json!({"non-message": SIGN_MESSAGE_TEXT})).unwrap();


    // failing validation if message doesn't match the primary type structure
    assert_eq!(cred.validate().unwrap_err(),  
        cred_err("message", "'message' is set to be in Envelope but not found in 'message'")
    );
    cred.types = from_value(json!({
        "EIP712Domain": domain_attrs(), "Envelope": [domain_type("non-message", "string")]
    })).unwrap();



    // passing field validation
    assert!(cred.validate().is_ok());
    // passing signature verification
    assert!(cred.verify(deps).is_ok());

    // passing replay check with passed argument messages
    assert!(cred.protect_reply(&env, param_msgs).is_ok());
    // passing replay check using a text from message["message"] 
    assert!(cred.protect_reply(&env, params_empty).is_ok());

}




#[test]
fn replay_eth_typed_nonce() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();

    let replay_hash = keccak256(&[
            SIGN_CHAIN_ID.as_bytes(),
            SIGN_CONTRACT_ADDRESS.as_bytes(),
        ].concat()
    );
    // let replay_address = "0xd4f16b04011cd5747044b98d668b505bb0df0e99".to_string();
    let replay_address = "0x".to_owned() + &hex::encode(&replay_hash[12..]);
    let replay_msg_address = "0x0ef13906b325aba3cb700fe97a6edf86dcfee89a".to_string();

    let params_msg = ReplayParams::new(SIGN_NONCE, CheckOption::Messages(
        vec![SIGN_MESSAGE_TEXT.to_string()])
    );
    let params_empty = ReplayParams::new(SIGN_NONCE, CheckOption::Nothing);


    let default_domain = Eip712Domain {
        name: Some("Token-Bound Accounts".to_string()),
        version: Some("1.1".to_string()),
        verifying_contract: Some(replay_address.clone()),
        chain_id: Some(0u64.into()),
        salt: None
    };

    let default_message : Eip712Message = from_value(json!({
        "message": SIGN_MESSAGE_TEXT,
        "nonce": SIGN_NONCE
    })).unwrap();


    let mut cred = EthTypedData {
        domain: default_domain.clone(),
        types: from_value(json!({ 
            "EIP712Domain": domain_attrs(),
            "Envelope": [
                domain_type("message",  "string"),
                domain_type("nonce", "uint256")
            ]
        })).unwrap(),
        primary_type: "Envelope".into(),
        message_property: None, // not set explictly yet
        message: default_message.clone(), 
        signature: Binary::from_base64("p1p1Pjl3LvVp2z1hAsUi4TExg9ULbUTH+spsjkQ7PEtVOqAeZrFFFokaG/KlPTl1q9Xvo6qeatZRva/zZxgo7xw=").unwrap(),
        signer : get_eth_signer(),
        cache: None,
    };


    // passing field validation
    assert!(cred.validate().is_ok());

    // without explicitly setting the property we are using the address hashed from message and nonce
    assert_eq!(cred.protect_reply(&env, params_msg.clone()).unwrap_err(),  ReplayError::InvalidEnvelope);
    assert_eq!(cred.protect_reply(&env, params_empty.clone()).unwrap_err(),  ReplayError::InvalidEnvelope);

    let mut dom_msg_cred = EthTypedData {
         domain: Eip712Domain { verifying_contract: Some(replay_msg_address), ..default_domain.clone() },
        ..cred.clone()
    };
    assert!(dom_msg_cred.protect_reply(&env, params_msg.clone()).is_ok());
    assert!(dom_msg_cred.protect_reply(&env, params_empty.clone()).is_ok());

    // the situation is flipped now
    cred.message_property = Some("message".into());
    dom_msg_cred.message_property = Some("message".into());

    // now it's only bytes of id + address VS the whole envelope so using a different name to match semantically 
    assert_eq!(dom_msg_cred.protect_reply(&env, params_msg.clone()).unwrap_err(),  ReplayError::AddressMismatch);
    assert_eq!(dom_msg_cred.protect_reply(&env, params_empty.clone()).unwrap_err(), ReplayError::AddressMismatch);

    
    // if there aren no argument messages, we just rely on the user seeing the messages and verifying address
    assert!(cred.protect_reply(&env, params_empty.clone()).is_ok());

    // when passed we are making sure that string(msgs) == string(message[self.message_property() ?? "message"])
    assert!(cred.protect_reply(&env, params_msg.clone()).is_ok());

    // fail if the messages are different
    assert!(cred.protect_reply(
        &env, ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec!["WRONG".to_string()]))
    ).is_err());
  

    // invalid nonce doesn't work
    cred.message.insert("nonce".into(), Value::Number((SIGN_NONCE + 1).into()));
    assert!(cred.protect_reply(&env, params_empty.clone()).unwrap_err() == ReplayError::InvalidNonce(SIGN_NONCE));

    // string nonce also works if it's parsable into u64
    cred.message.insert("nonce".into(), Value::String(SIGN_NONCE.to_string()));
    assert!(cred.protect_reply(&env, params_empty.clone()).is_ok());
    assert!(cred.verify(deps).is_ok()); // verification is also ok (to be bytes)


    // invalid non-numeric (u64) nonce works as if the nonce hasn't been set
    // defaulting to a replay address that uses messages and nonce
    cred.message.insert("nonce".into(), Value::String("random".to_string()));
    dom_msg_cred.message.insert("nonce".into(), Value::String("random".to_string()));

    assert_eq!(cred.protect_reply(&env, params_empty.clone()).unwrap_err(),  ReplayError::InvalidEnvelope);
    assert!(dom_msg_cred.protect_reply(&env, params_empty.clone()).is_ok());


    // fix to be like it was
    cred.message.insert("nonce".into(), Value::Number(SIGN_NONCE.into()));

    // still passing signature verification
    let info = cred.verify(deps).unwrap();

    if let Some(CredentialAddress::Evm(addr)) = info.address {
        assert_eq!(addr, get_eth_signer());
    } else {
        panic!("Expected Evm address but got {:?}", info.address);
    }
    assert_eq!(info.name, CredentialName::EthTypedData);
    assert_eq!(info.hrp, None);

    // setting the cached hash values to optimize the replay check
    if let Some(InfoExtension::EthTypedData(info)) = info.extension {
        assert_eq!(info.pre_hash, prehash_eth_typed("Token-Bound Accounts","1.1",false));
        assert_eq!(info.addr_hash, Some(replay_address[2..].to_string()));
        println!("EthTypedData parsed inh: {:?}", info.addr_hash);
        cred.cache = Some(info)
    } else {
        panic!("Expected EthTypedInfo but got {:?}", info.extension);
    }

    // using cached values works as well
    assert!(cred.validate().is_ok());
    println!("Cached res: {:?}", cred.protect_reply(&env, params_empty.clone()));
    assert!(cred.protect_reply(&env, params_empty).is_ok());
    assert!(cred.protect_reply(&env, params_msg).is_ok());
    assert!(cred.verify(deps).is_ok());
    
}


fn bin_hash_hex<S: Display + Serialize>(msgs: Vec<S>) -> String {
    hex::encode(&keccak256(&to_json_binary(&msgs).unwrap()))
}


fn msg_address<S: Display + Serialize>(msgs: Vec<S>) -> String {
    let str = match msgs.len() {
        0 => String::new(),
        1 => msgs[0].to_string(),
        _ => bin_hash_hex(msgs)
    };

   let replay_msg_hash = keccak256(
        &[
            SIGN_CHAIN_ID.as_bytes(),
            SIGN_CONTRACT_ADDRESS.as_bytes(),
            str.as_bytes(),
            &SIGN_NONCE.to_be_bytes()
        ].concat()
    );
    "0x".to_owned() + &hex::encode(&replay_msg_hash[12..])
}





#[test]
fn replay_eth_typed_message_strings() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();

    use CheckOption::*;

    let address = "0x0ef13906b325aba3cb700fe97a6edf86dcfee89a".to_string();
    assert_eq!(msg_address(vec![SIGN_MESSAGE_TEXT]), address);

    
    let params_msg = ReplayParams::new(SIGN_NONCE, Messages(vec![SIGN_MESSAGE_TEXT.into()]));
    let params_str = ReplayParams::new(SIGN_NONCE, Text(SIGN_MESSAGE_TEXT.into()));
    let params_empty = ReplayParams::new(SIGN_NONCE, Nothing);


    let mut cred = EthTypedData {
        types: from_value(json!({ 
            "EIP712Domain": domain_attrs(),
            "Prompt": [domain_type("text",  "string")]
        })).unwrap(),
        primary_type: "Prompt".into(),
        message_property: Some("text".into()),
        message: from_value(json!({ "text": SIGN_MESSAGE_TEXT})).unwrap(),
        signature: Binary::from_base64(
            "KYU+RvUyJ4I48KuV30/pGYs4GzEa+Woc7TudLiiyl/pVq0cifALlhMsLR0ETWNQGK3EUfuV20BXZPZ6Qar7jwhs="
        ).unwrap(),
        ..def_cred(address)
    };

    assert!(cred.validate().is_ok());
    assert!(cred.protect_reply(&env, params_msg.clone()).is_ok());
    assert!(cred.protect_reply(&env, params_str.clone()).is_ok());
    assert!(cred.protect_reply(&env, params_empty.clone()).is_ok());
    assert!(cred.verify(deps).is_ok());


    // ------ One text string ------
    cred.types.insert("Prompt".into(),vec![domain_type("texts", "string[]")]);
    cred.message = from_value(json!({ "texts": [SIGN_MESSAGE_TEXT] })).unwrap();
    // Same replay address as before. Only signature is different
    cred.signature = Binary::from_base64("3tLiiBh+WwcPA247Y+MyDUS82d97e1o1d5PBqri4xpEyKbSAsOIo+M1/7et2BTjFtD1U7PWQWu7L7oz7gCsK6Rw=").unwrap();
    
    
    println!("Cred validate {:?}", cred.validate());
    println!("Cred protect empty: {:?}", cred.protect_reply(&env, params_empty.clone()));
    println!("Cred protect msgs: {:?}", cred.protect_reply(&env, params_msg.clone()));
    println!("Cred protect text: {:?}", cred.protect_reply(&env, params_str.clone()));
    println!("Cred verify: {:?}", cred.verify(deps));


    assert!(cred.validate().is_ok());
    assert!(cred.protect_reply(&env, params_msg.clone()).is_ok());
    assert!(cred.protect_reply(&env, params_str.clone()).is_ok());
    assert!(cred.protect_reply(&env, params_empty.clone()).is_ok());
    assert!(cred.verify(deps).is_ok());


    // ------ Multiple text strings ------
    let msgs = vec![SIGN_MESSAGE_TEXT, "Foo", "Bar", "Hello"]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    cred.message = from_value(json!({ "texts": msgs.clone() })).unwrap();
    cred.domain.verifying_contract = Some(msg_address(msgs.clone()));
    cred.signature = Binary::from_base64("ThVoNC3hl7bPmaMN5IQxGGlPWM2bRATzZuQ1F1LTCs0GaVe55dG/EdRvlcy4e1WK5jf5fEdxi/oAUFRJ4t7XkBw=").unwrap();

    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, Messages(msgs.clone()))).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, Text(bin_hash_hex(msgs.clone())))).is_ok());
    assert!(cred.protect_reply(&env, params_empty.clone()).is_ok());



    let res = cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, Messages(msgs.clone())));
    println!("Cred res: {:?}", res);
    assert!(res.is_ok(), "Credential validation failed: {:?}", res);


}





#[test]
fn replay_eth_typed_message_actions() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();

    let empty = ReplayParams::new(SIGN_NONCE, CheckOption::Nothing);
    
    //  ------ The whole message itself is the action -----

    let address = "0x571fe8e963ef3f9e7944d62640288be7319ce6e9".to_string();

    let recipient = "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn".to_string();
    let collection = "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn".to_string();
    let token_id = "1".to_string();

    let msg = ExecuteMsg::TransferToken {
        collection: collection.clone(),
        recipient: recipient.clone(),
        token_id: token_id.clone()
    };
    let msg_str = to_json_string(&msg).unwrap();
    
    let mut cred = EthTypedData {
        types: from_value(json!({ 
            "EIP712Domain": domain_attrs(),
            "Transfer": [
                domain_type("collection", "string"),
                domain_type("recipient", "string"),
                domain_type("token_id", "string")
            ],
            "AccountAction": [domain_type("transfer_token",  "Transfer")]
        })).unwrap(),
        primary_type: "AccountAction".into(),
        message_property: None,
        message: from_value(json!({
            "transfer_token": {
                "collection": collection,
                "recipient": recipient,
                "token_id": token_id,
            }
        })).unwrap(),
        signature: Binary::from_base64(
            "kNsp8lSOk2sQbtbN48A8/IUqjljUdYSZBK5hsFMqJadFdxJsJqR4VFaaerUfSgbuNeZLus0o+tgnE5GbYdnH/Bs="
        ).unwrap(),
        ..def_cred(address)
    };

    assert!(cred.validate().is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![msg_str.clone().into()]))).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Text(msg_str.clone()))).is_ok());
    println!("Cred: {:?}", cred.protect_reply(&env,ReplayParams::new(SIGN_NONCE, CheckOption::Nothing)));
    
    assert!(cred.protect_reply(&env, empty.clone()).is_ok());
    assert!(cred.verify(deps).is_ok());

    
    //  ------ Action is a propery of the message -----

    cred.message = from_value(json!({
        "action": {
            "transfer_token": {
                "collection": collection,
                "recipient": recipient,
                "token_id": token_id,
            }
        },
        "text": "TBA account action"
    })).unwrap();
    cred.types.insert("Prompt".into(), vec![
        domain_type("action", "AccountAction"),
        domain_type("text", "string")
    ]);
    cred.primary_type = "Prompt".into();
    cred.message_property = Some("action".into());
    cred.signature = Binary::from_base64(
        "S1lR/bSGu/r4Pftflc/y8vljzLsv5Huq745BWtvl9kQ5MugymZWzMrHYeHSRcBAJMy8+EgqRoYBBfFL8L2ituBw="
    ).unwrap();
    cred.domain.verifying_contract = Some("0x571fe8e963ef3f9e7944d62640288be7319ce6e9".to_string());

   // let text = to_json_string(&
    assert!(cred.validate().is_ok());
    assert!(cred.protect_reply(&env, empty.clone()).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![msg_str.clone().into()]))).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Text(msg_str.clone().into()))).is_ok());
    assert!(cred.verify(deps).is_ok());


    //  ------ List of one element as message property -----
    cred.types.insert("Prompt".into(), vec![
        domain_type("actions", "AccountAction[]"),
        domain_type("text", "string")
    ]);
    cred.message = from_value(json!({
        "actions": [{
            "transfer_token": {
                "collection": collection,
                "recipient": recipient,
                "token_id": token_id,
            }
        }],
        "text": "TBA account action"
    })).unwrap();

    cred.signature = Binary::from_base64(
        "gItgh83Rj3GC+fYgFr5MyM8Q/7cddEKsX59T0fYU+fY6KBou/nAnpQBpC66qsjvkjXVryvI6Vsbfb4+lcMQNKRw="
    ).unwrap();



    assert!(cred.validate().is_ok());
    assert!(cred.protect_reply(&env, empty.clone()).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![msg_str.clone().into()]))).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Text(msg_str.clone().into()))).is_ok());
    assert!(cred.verify(deps).is_ok());



    //  ------ List of multiple actions inside the primary message -----


    println!("Cred validate {:?}", cred.protect_reply(&env, empty.clone()));
    println!("Cred protect empty: {:?}", cred.protect_reply(&env, empty.clone()));
    println!("Cred protect msgs: {:?}", cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![msg_str.clone().into()]))));
    println!("Cred protect text: {:?}", cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Text(msg_str.clone().into()))));
    println!("Cred verify: {:?}", cred.verify(deps));

    assert!(cred.validate().is_ok());
    assert!(cred.protect_reply(&env, empty.clone()).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Messages(vec![msg_str.clone().into()]))).is_ok());
    assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Text(msg_str.clone().into()))).is_ok());
    assert!(cred.verify(deps).is_ok());

}



