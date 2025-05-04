use cosmwasm_std::testing::{mock_dependencies, mock_info};
use saa_common::{stores::{HAS_NATIVES, VERIFYING_CRED_ID}, wasm::storage::save_credential, Verifiable};
use smart_account_auth::{storage::{get_all_credentials, load_count, remove_credential, remove_credential_smart, reset_credentials, stores::{ACCOUNT_NUMBER, CREDENTIAL_INFOS}}, Caller, Credential, CredentialName, CredentialsWrapper};
use crate::vars::{cred_data_non_native, cred_data_only_native, credential_data, default_cred_count, get_cosmos_arbitrary, get_eth_personal, get_mock_env, get_passkey};


#[test]
fn credential_crds_work() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;

    let eth_cred : Credential = get_eth_personal().into();
    let cosmos_cred : Credential = get_cosmos_arbitrary().into();
    let passkey_cred : Credential = get_passkey().into();

    // Saving credentials
    save_credential(storage, &eth_cred.id(), &eth_cred.info()).unwrap();
    save_credential(storage, &cosmos_cred.id(), &cosmos_cred.info()).unwrap();
    save_credential(storage, &passkey_cred.id(), &passkey_cred.info()).unwrap();
    VERIFYING_CRED_ID.save(storage, &eth_cred.id()).unwrap();

    assert_eq!(load_count(storage), 3);

    // remove simple
    remove_credential(storage, &cosmos_cred.id()).unwrap();
    assert_eq!(load_count(storage), 2);
    
    // remove smart veryfying
    remove_credential_smart(storage, &eth_cred.id()).unwrap();
    assert_eq!(load_count(storage), 1);
    // moved forward to the next one
    assert_eq!(VERIFYING_CRED_ID.load(storage).unwrap(), passkey_cred.id());
    
    // remove all
    reset_credentials(storage).unwrap();
    assert_eq!(load_count(storage), 0);

    let native : Credential = Caller::from("alice").into();

    // Saving again but now with caller
    save_credential(storage, &eth_cred.id(), &eth_cred.info()).unwrap();
    save_credential(storage, &cosmos_cred.id(), &cosmos_cred.info()).unwrap();
    save_credential(storage, &passkey_cred.id(), &passkey_cred.info()).unwrap();
    save_credential(storage, &native.id(), &native.info()).unwrap();
    VERIFYING_CRED_ID.save(storage, &native.id()).unwrap();
    HAS_NATIVES.save(storage, &true).unwrap();

    // none of the two should change
    remove_credential_smart(storage, &passkey_cred.id()).unwrap();
    assert_eq!(VERIFYING_CRED_ID.load(storage).unwrap(), native.id());
    assert_eq!(HAS_NATIVES.load(storage).unwrap(), true);

    remove_credential_smart(storage, &native.id()).unwrap();
    assert_eq!(VERIFYING_CRED_ID.load(storage).unwrap(), eth_cred.id());
    assert_eq!(HAS_NATIVES.load(storage).unwrap(), false);
    assert_eq!(load_count(storage), 2);
}




#[test]
fn save_credential_data_work() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;
    let env = get_mock_env();
    let info = mock_info("", &[]);

    let data = cred_data_non_native();
    let saved = data.save(deps.api, storage, &env, &info).unwrap();
    
    // asserted saved data is same as initial
    assert_eq!(saved.count(), data.count());
    assert_eq!(ACCOUNT_NUMBER.load(storage).unwrap_or_default(), 1);


    // All credentials are saved stored info matches
    for cred in data.credentials.iter() {
        let info = CREDENTIAL_INFOS.load(storage, cred.id()).unwrap();
        assert_eq!(info, cred.info());
    }

    // No extra credentials were saved
    assert_eq!(load_count(storage), data.count());

    // Verifying credential id is stored properly
    let ver = VERIFYING_CRED_ID.load(storage).unwrap();
    let first = data.credentials.first().unwrap();
    assert!(first.id() == ver && data.primary_id() == ver);

    // should't have any natives callers
    assert!(!HAS_NATIVES.load(storage).unwrap_or(false));
}




#[test]
fn save_cred_data_with_native_caller() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;
    let env = get_mock_env();

    let alice = mock_info("alice", &[]);
    let data = credential_data()
                .with_native_caller(&alice)
                .save(deps.api, storage, &env, &alice)
                .unwrap();

    // extra Caller credential is saved
    assert_eq!(load_count(storage), default_cred_count() + 1);
    assert_eq!(data.credentials.last().unwrap(), &Credential::Native(Caller::from(&alice)));

    // should have natives callers
    assert!(HAS_NATIVES.load(storage).unwrap_or(false));

    reset_credentials(storage).unwrap();


    let data = cred_data_only_native(alice.sender.as_str())
                    .save(deps.api, storage, &env, &alice)
                    .unwrap();
    
    let all = get_all_credentials(storage).unwrap();
    let (id, info) = all.first().unwrap();
    assert!(id == &data.primary_id() && id == "alice");
    assert!(HAS_NATIVES.load(storage).unwrap_or_default());
    assert_eq!(VERIFYING_CRED_ID.load(storage).unwrap(), *id);
    assert_eq!(CredentialName::Native.to_string(), info.name);
}
