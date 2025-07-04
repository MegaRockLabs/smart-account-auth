use crate::utils::{base_credentials,  get_mock_deps, get_mock_env, SIGN_MESSAGE_TEXT};
use smart_account_auth::{CheckOption, ReplayParams, CredentialData, ReplayProtection, ReplayProtectionWrapper};
use saa_common::ReplayError;


mod eip712;

/* 

#[test]
fn replay_attack_check_data() {
    let _mock = get_mock_deps();
    let env = get_mock_env();
    let mut data = CredentialData::new(base_credentials(), None);
    // Verify the credentials individually

    let nonce = data.nonce.unwrap_or_default().u64();
    let msgs = vec![SIGN_MESSAGE_TEXT.to_string()];

    let params = ReplayParams::new(nonce, CheckOption::Messages(msgs.clone()));

    // skip last until prefix is fixed from stargaze
    for cred in data.credentials.iter() {
        let res = cred.protect_reply(&env, params.clone());
        // println!("Credential replay attack res: {:?}", res);
        // assert!(cred.verify().is_ok(), "Native verify code of Credential failed");
        assert!(res.is_ok(), "Cosmwasm verify code of Credential failed");
    }

    // Verify the whole wrapper data
    // assert!(data.verify().is_ok(), "Native verify code of Credential Data failed");
    let res = data.protect_reply(&env, params.clone());
    assert!(res.is_ok(), "Cosmwasm verify code of Credential Data failed");

    // Shouldn't work with different messages
    let bad_msgs_res = data.protect_reply(
        &env, ReplayParams::new(nonce, CheckOption::Messages(vec!["bad message".to_string()]))
    );
    assert!(bad_msgs_res.unwrap_err() == ReplayError::InvalidEnvelope);

    // Should work when messages are empty
    let empty_msgs_res = data.protect_reply(&env, 
        ReplayParams::new(nonce, CheckOption::Messages(vec![]))
    );
    assert!(empty_msgs_res.unwrap_err() == ReplayError::InvalidEnvelope);

    // Work without optimization mode
    let deser_res = data.protect_reply(
        &env, ReplayParams::new(nonce, CheckOption::Nothing)
    );
    assert!(deser_res.unwrap_err() == ReplayError::InvalidEnvelope);

    data.nonce = Some((nonce + 1).into()); // let's assume user had used a different nonce
    // Shouldn't work with different nonce
    let bad_nonce_res = data.protect_reply(
        &env, ReplayParams::new(nonce, CheckOption::Messages(msgs))
    );

    // using serialization so don't know which field is wrong
    assert!(bad_nonce_res.unwrap_err() == ReplayError::InvalidNonce(nonce));
}

 */