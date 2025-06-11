use crate::utils::{alice_info, base_credentials, get_mock_deps, get_mock_env, get_typed_data, SIGN_MESSAGE_TEXT};
use saa_common::ReplayError;
use smart_account_auth::{CredentialData, 
    ReplayProtection, ReplayProtectionWrapper
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
    let _mock = get_mock_deps();
    let env = get_mock_env();
    let _info = alice_info();

    let cred = get_typed_data();
    let msgs = vec![SIGN_MESSAGE_TEXT.to_string()];

    let res = cred.check_replay(&env, &Some(msgs), 0);
    assert!(res.is_ok(), "Typed data replay with passed messages check failed");

    let res = cred.check_replay::<String>(&env, &None, 0);
    assert!(res.is_ok(), "Typed data replay attack check failed");
}



