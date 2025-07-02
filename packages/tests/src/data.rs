use crate::utils::{alice_info, base_credentials, get_mock_deps, get_mock_env, ALICE_ADDR, SIGN_MESSAGE_TEXT, SIGN_NONCE};
use saa_common::{CredentialAddress, CredentialName};
use smart_account_auth::{CheckOption, ReplayParams, Caller, Credential, CredentialData, CredentialsWrapper, Verifiable};




#[test]
fn data_is_verifyable() {
    let mock = get_mock_deps();
    let deps = mock.as_ref();
    let env = get_mock_env();
    let data = CredentialData::new(base_credentials(), None);
    // Verify the credentials individually

    let messages = vec![SIGN_MESSAGE_TEXT.to_string()];
    let mut addresses : Vec<CredentialAddress> = Vec::with_capacity(2);

    // skip last until prefix is fixed from stargaze
    for cred in data.credentials.iter() {
        let info = cred.verify(mock.as_ref());
        println!("Credential verify info: {:?}", info);
        //assert!(cred.verify().is_ok(), "Native verify code of Credential failed");
        assert!(info.is_ok(), "Cosmwasm verify code of Credential failed");

        let info = info.unwrap();

        match info.name {
            CredentialName::CosmosArbitrary => {
                if let Some(CredentialAddress::Bech32(addr)) = info.address {
                    println!("CosmosArbitrary address: {}", addr);
                    assert!(addr.as_str().ends_with("luz"), "Invalid CosmosArbitrary address");
                    addresses.push(CredentialAddress::Bech32(addr));
                } else {
                    panic!("CosmosArbitrary info should have a Bech32 address");
                }
            },
            CredentialName::EthPersonalSign => {
                if let Some(CredentialAddress::Evm(addr)) = info.address {
                    println!("EthPersonalSign address: {}", addr);
                    let str = addr.as_str();
                    assert!(str.len() == 42 && str.ends_with("91a"), "Invalid EthPersonalSign address");
                    addresses.push(CredentialAddress::Evm(addr));
                } else {
                    panic!("EthPersonalSign info should have an Evm address");
                }
            },
            _ => {}
        }
    }

    // Verify the whole wrapper data
    // assert!(data.verify().is_ok(), "Native verify code of Credential Data failed");
    let res = data.verify(
        deps, &env, &alice_info(), ReplayParams::new(SIGN_NONCE, CheckOption::Messages(messages)
    ));
    println!("Credential Data verify result: {:?}", res);
    assert!(res.is_ok(), "Cosmwasm verify code of Credential Data failed");


    let verified = res.unwrap();
    assert_eq!(verified.addresses, addresses, "Verified credentials length mismatch");


}



#[test]
fn with_caller_works() {

    let base_creds = base_credentials();
    let base_count = base_creds.len();

    let mut no_caller_data = CredentialData::new(base_creds, None);
    assert_eq!(base_count, no_caller_data.credentials.len());
    
    // Alice is a dummy address that isn't used
    assert!(no_caller_data.validate(ALICE_ADDR).is_ok(), "Base Credential data should be valid");

    no_caller_data.use_native = Some(true);
    assert_eq!(base_count, no_caller_data.credentials.len());
    assert!(no_caller_data.validate(ALICE_ADDR).is_err(), "With caller is set but address hasn't been passed");

    
    let data = no_caller_data.with_native(ALICE_ADDR);
    assert_eq!(base_count + 1, data.credentials.len());
    assert!(data.validate(ALICE_ADDR).is_ok());

    // Try to call again. Should overwrite the previous one; // NOTE: works MessageInfo same as with String
    let data = data.with_native(&alice_info());

    // should still be of the same length and not have duplicates
    assert_eq!(base_count + 1, data.credentials.len());

}




#[test]
fn only_caller_credential() {

    let native : &str = "alice";

    let data = CredentialData::new(vec![], Some(true))
                                .with_native(native);

    assert_eq!(data.credentials.len(), 1);
    assert_eq!(data.primary_index(), None);
    assert_eq!(data.primary_id(), native.to_string());

    let caller = Caller::from(native);
    let native : Credential = caller.into();

    assert_eq!(*data.primary(), native);
}
