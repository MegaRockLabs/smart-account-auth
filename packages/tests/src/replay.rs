use crate::utils::{alice_info, base_credentials, domain_attrs, get_mock_deps, get_mock_env, SIGN_MESSAGE_TEXT};
use saa_common::{Binary, ReplayError, Verifiable};
use serde_json::{from_value, json};
use smart_account_auth::{types::Eip712Domain, CredentialData, EthTypedData, ReplayProtection, ReplayProtectionWrapper
};



#[test]
fn replay_attack_check_data() {
    let _mock = get_mock_deps();
    let env = get_mock_env();
    let mut data = CredentialData::new(base_credentials(), None);
    // Verify the credentials individually

    let nonce = data.nonce.unwrap_or_default().u64();
    let msgs = Some(vec![SIGN_MESSAGE_TEXT.to_string()]);

    // skip last until prefix is fixed from stargaze
    for cred in data.credentials.iter() {
        let res = cred.check_replay(&env, &msgs, nonce);
        // println!("Credential replay attack res: {:?}", res);
        // assert!(cred.verify().is_ok(), "Native verify code of Credential failed");
        assert!(res.is_ok(), "Cosmwasm verify code of Credential failed");
    }

    // Verify the whole wrapper data
    // assert!(data.verify().is_ok(), "Native verify code of Credential Data failed");
    let res = data.check_replay(&env, &msgs, nonce);
    assert!(res.is_ok(), "Cosmwasm verify code of Credential Data failed");

    // Shouldn't work with different messages
    let bad_msgs_res = data.check_replay(&env, &Some("Foo".into()), nonce);
    assert!(bad_msgs_res.unwrap_err() == ReplayError::InvalidEnvelope);

    // Should work when messages are empty
    let empty_msgs_res = data.check_replay::<String>(&env, &Some(vec![]), nonce);
    assert!(empty_msgs_res.unwrap_err() == ReplayError::InvalidEnvelope);

    // Should work when messages aren't set (through deserialization) 
    let deser_res = data.check_replay::<String>(&env, &None, nonce);
    assert!(deser_res.unwrap() == ());

    data.nonce = Some((nonce + 1).into()); // let's assume user had used a different nonce
    // Shouldn't work with different nonce
    let bad_nonce_res = data.check_replay(&env, &msgs, nonce);

    // using serialization so don't know which field is wrong
    assert!(bad_nonce_res.unwrap_err() == ReplayError::InvalidNonce(nonce));
}


#[test]
fn replay_attack_eth_typed() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();
    let _info = alice_info();

    let cred = EthTypedData {
        signer : "0xac03048da6065e584d52007e22c69174cdf2b91a".to_string(),

        domain: Eip712Domain {
            name: Some("Token-Bound Accounts".to_string()),
            version: Some("1.1".to_string()),
            verifying_contract: Some("0x0ef13906b325aba3cb700fe97a6edf86dcfee89a".to_string()),
            chain_id: Some(0u64.into()),
            salt: None
        },

        types: from_value(json!({
            "EIP712Domain": domain_attrs(),
            "Envelope": [
                { "name": "message",  "type": "string" },
            ]
        })).unwrap(),
        
        signature: Binary::from_base64(
            "kfeJTRwU9zdDeX13YUtcL9LTaOsHJlZRXOnC+aHglER/ORs2ggZL8lj6IjoqJeorWXcp9A+dfs9lDkgmrzp3vxw="
        ).unwrap(),

        message: from_value(json!({
            "message": SIGN_MESSAGE_TEXT 
        })).unwrap(),

        primary_type: "Envelope".to_string(),

        message_property: None
    };

    let msgs = vec![SIGN_MESSAGE_TEXT.to_string()];

    let res = cred.check_replay(&env, &Some(msgs), 0);
    assert!(res.is_ok(), "Typed data replay with passed messages check failed");

    let res = cred.check_replay::<String>(&env, &None, 0);
    assert!(res.is_ok(), "Typed data replay attack check failed");

    let ver_res = cred.verify(deps);
    println!("Typed data replay attack res: {:?}", ver_res);
    assert!(ver_res.is_ok(), "Typed data verify failed");
}



