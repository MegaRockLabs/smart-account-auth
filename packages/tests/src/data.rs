use cosmwasm_std::{testing::{message_info, mock_dependencies}, Addr};
use smart_account_auth::{Caller, Credential, CredentialData, traits::{CredentialsWrapper, Verifiable}};
use crate::vars::{default_cred_count, cred_data_non_native};





#[test]
fn data_is_verifyable() {
    let mock = mock_dependencies();
    let api = mock.as_ref().api;

    let data = cred_data_non_native();
    // Verify the credentials individually
    for cred in data.credentials.iter() {
        assert!(cred.verify().is_ok(), "Native verify code of Credential failed");
        assert!(cred.verify_cosmwasm(api).is_ok(), "Cosmwasm verify code of Credential failed");
    }

    // Verify the whole wrapper data
    assert!(data.verify().is_ok(), "Native verify code of Credential Data failed");
    assert!(data.verify_cosmwasm(api).is_ok(), "Cosmwasm verify code of Credential Data failed");
}



#[test]
fn with_caller_works() {

    let creds_count = default_cred_count();

    let mut no_caller_data = cred_data_non_native();
    assert_eq!(creds_count, no_caller_data.credentials.len());
    
    assert!(no_caller_data.validate().is_ok(), "Base Credential data should be valid");

    no_caller_data.use_native = Some(true);
    assert_eq!(creds_count, no_caller_data.credentials.len());
    assert!(no_caller_data.validate().is_err(), "With caller is set but address hasn't been passed");

    
    let data = no_caller_data.with_native_caller("alice");
    assert_eq!(creds_count + 1, data.credentials.len());
    assert!(data.validate().is_ok());

    // Try to call again. Should overwrite the previous one; // NOTE: works MessageInfo same as with String
    let data = data.with_native_caller(&message_info(&Addr::unchecked("alice"), &[]));

    // should still be of the same length and not have duplicates
    assert_eq!(creds_count + 1, data.credentials.len());

}


#[test]
fn cred_data_index_edges() {
    
}


#[test]
fn only_caller_credential() {

    let native : &str = "alice";

    let data = CredentialData {
        use_native: Some(true),
        credentials: vec![],
        primary_index: None,
    }.with_native_caller(native);

    assert_eq!(data.count(), 1);
    assert_eq!(data.primary_index(), None);
    assert_eq!(data.primary_id(), native.to_string());

    let caller = Caller::from(native);
    let native : Credential = caller.into();

    assert_eq!(data.primary(), native);
}
