use cosmwasm_std::{testing::{message_info, mock_dependencies, MockApi}, Storage};

use crate::utils::{
    cred_data_non_native, cred_data_only_native, 
    get_cosmos_arbitrary, get_eth_personal, 
    credential_data, default_cred_count, 
    get_mock_env, get_passkey
};

use cw_auths::{
    saa_types::{
        traits::{CredentialsWrapper, Verifiable},
        Credential, CredentialId, CredentialData, CredentialInfo, CredentialName,
        Caller, StorageError, AuthError 
    },
    stores::{ACCOUNT_NUMBER, CREDENTIAL_INFOS, HAS_NATIVES, VERIFYING_ID},
    get_stored_credentials, reset_credentials, 
    save_credentials, update_credentials,
    credential_count,UpdateOperation
    
};


fn checked_remaining(
    storage: &mut dyn Storage,
    remaining: Vec<(CredentialId, CredentialInfo)>,
    check_verifying: bool,
    check_natives: bool,
    verifying_id: Option<CredentialId>,
) -> Result<(), StorageError> {
    if remaining.is_empty() {
        if check_verifying {
            VERIFYING_ID.remove(storage);
        }
        if check_natives {
            HAS_NATIVES.save(storage, &false)?;
        }
        return Ok(());
    }
    
    if check_verifying {
        let id = verifying_id.unwrap_or(remaining[0].0.clone());
        VERIFYING_ID.save(storage, &id)?;
    }

    if check_natives {
        let has: bool = remaining.iter().any(|(_, info)| info.name ==  CredentialName::Native);
        HAS_NATIVES.save(storage, &has)?;
    }
    Ok(())
}


fn remove_credential_smart(
    storage: &mut dyn Storage,
    id: &CredentialId,
) -> Result<(), StorageError> {
    remove_credential(storage, id).map_err(|_| StorageError::NotFound)?;
    let remaining = get_stored_credentials(storage)?.records;
    let check_ver = VERIFYING_ID.load(storage)
        .map_err(|_| StorageError::NotFound)
        ? == *id;

    checked_remaining(
        storage, 
        remaining, 
        check_ver,
        true, 
        None
    )
}



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
    VERIFYING_ID.save(storage, &eth_cred.id()).unwrap();

    assert_eq!(credential_count(storage), 3);

    // remove simple
    remove_credential(storage, &cosmos_cred.id()).unwrap();
    assert_eq!(credential_count(storage), 2);
    
    // remove smart veryfying
    remove_credential_smart(storage, &eth_cred.id()).unwrap();
    assert_eq!(credential_count(storage), 1);
    // moved forward to the next one
    assert_eq!(VERIFYING_ID.load(storage).unwrap(), passkey_cred.id());
    
    // remove all
    reset_credentials(storage, true, true).unwrap();
    assert_eq!(credential_count(storage), 0);

    let native : Credential = Caller::from("alice").into();

    // Saving again but now with caller
    save_credential(storage, &eth_cred.id(), &eth_cred.info()).unwrap();
    save_credential(storage, &cosmos_cred.id(), &cosmos_cred.info()).unwrap();
    save_credential(storage, &passkey_cred.id(), &passkey_cred.info()).unwrap();
    save_credential(storage, &native.id(), &native.info()).unwrap();
    VERIFYING_ID.save(storage, &native.id()).unwrap();
    HAS_NATIVES.save(storage, &true).unwrap();

    // none of the two should change
    remove_credential_smart(storage, &passkey_cred.id()).unwrap();
    assert_eq!(VERIFYING_ID.load(storage).unwrap(), native.id());
    assert_eq!(HAS_NATIVES.load(storage).unwrap(), true);

    remove_credential_smart(storage, &native.id()).unwrap();
    assert_eq!(VERIFYING_ID.load(storage).unwrap(), eth_cred.id());
    assert_eq!(HAS_NATIVES.load(storage).unwrap(), false);
    assert_eq!(credential_count(storage), 2);
}



fn save_credential(storage: &mut dyn Storage, id: &str, info: &CredentialInfo) 
    -> Result<(), AuthError> {
    CREDENTIAL_INFOS.save(storage, id.to_string(), info)
        .map_err(|e| StorageError::Write("credential".into(), e.to_string()).into())    
}


fn remove_credential(storage: &mut dyn Storage, id: &str) -> Result<(), AuthError> {
    CREDENTIAL_INFOS.remove(storage, id.to_string());
    Ok(())
}



#[test]
fn save_credential_data_work() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;
    let env = get_mock_env();

    let data = cred_data_non_native();
    let api = MockApi::default();

    let saved = save_credentials(
        deps.api, storage, &env, &message_info(&api.addr_make("bob"), &[]), &data
    ).unwrap();
    
    // asserted saved data is same as initial
    assert_eq!(saved.credentials.len(), data.credentials.len());
    assert_eq!(ACCOUNT_NUMBER.load(storage).unwrap_or_default(), 1);


    // All credentials are saved stored info matches
    for cred in data.credentials.iter() {
        let info = CREDENTIAL_INFOS.load(storage, cred.id()).unwrap();
        assert_eq!(info, cred.info());
    }

    // No extra credentials were saved
    assert_eq!(credential_count(storage), data.credentials.len());

    // Verifying credential id is stored properly
    let ver = VERIFYING_ID.load(storage).unwrap();
    let first = data.credentials.first().unwrap();
    assert!(first.id() == ver && data.primary_id() == ver);

    // should't have any natives callers
    assert!(!HAS_NATIVES.load(storage).unwrap_or(false));
}




#[test]
fn save_cred_data_with_native() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let storage = deps.storage;
    let env = get_mock_env();

    let api = MockApi::default();
    let alice_addr = api.addr_make("alice");

    let alice = message_info(&alice_addr, &[]);

    let data = save_credentials(deps.api, storage, &env, &alice, &credential_data()).unwrap();

    // extra Caller credential is saved
    assert_eq!(credential_count(storage), default_cred_count() + 1);
    assert_eq!(data.credentials.last().unwrap(), &Credential::Native(Caller::from(alice.sender.as_str())));

    // should have natives callers
    assert!(HAS_NATIVES.load(storage).unwrap_or(false));

    reset_credentials(storage, true, true).unwrap();

    let data = save_credentials(
        deps.api, storage, &env, &alice, &cred_data_only_native(alice.sender.as_str()
    )).unwrap();

    let all = get_stored_credentials(storage).unwrap().records;
    let (id, info) = all.first().unwrap();
    println!("id: {}, info: {:?}", id, info);
    println!("alice: {}", alice.sender.as_str());
    println!("primary: {}", data.primary_id());
    println!("data: {:?}", data);
    assert!(id == &data.primary_id() && id == alice.sender.as_str());
    assert!(HAS_NATIVES.load(storage).unwrap_or_default());
    assert_eq!(VERIFYING_ID.load(storage).unwrap(), *id);
    assert_eq!(CredentialName::Native, info.name);
}






#[test]
fn update_cred_data_remove_simple() {
    let mut mocks = mock_dependencies();
    let deps = mocks.as_mut();
    let api = deps.api;
    let storage = deps.storage;
    let env = get_mock_env();

    let mock_api: MockApi = MockApi::default();
    let alice_addr = mock_api.addr_make("alice");
    let alice = message_info(&alice_addr, &[]);

    let eth_cred : Credential = get_eth_personal().into();
    let cosmos_cred : Credential = get_cosmos_arbitrary().into();
    let passkey_cred : Credential = get_passkey().into();
    let alice_cred : Credential = Caller::from(alice.sender.as_str()).into();

    let data= CredentialData{
                credentials: vec![passkey_cred.clone(), eth_cred.clone()],
                use_native: Some(true),
                primary_index: None,
            };

    let data = save_credentials(
        api, storage, &env, &alice, &data
    ).unwrap();

    assert_eq!(credential_count(storage), 3);
    
    // error due to invalid arguments
    let empty = UpdateOperation::Remove(vec![]);
    assert!(update_credentials(api, storage, empty).is_err());

    // ok but no change cause the id is not there
    let op = UpdateOperation::Remove(vec![cosmos_cred.id()]);
    assert!(update_credentials(api, storage, op.clone()).is_ok());

    // ok but removing verifying credential
    let op = UpdateOperation::Remove(vec![passkey_cred.id()]);
    assert!(update_credentials(api, storage, op.clone()).is_ok());
    assert!(credential_count(storage) == 2);
    assert_eq!(VERIFYING_ID.load(storage).unwrap(), eth_cred.id());

    // ok but same thing doesnt't do anything
    assert!(update_credentials(api, storage, op.clone()).is_ok());


    // ok but can't use alice anymore
    let op = UpdateOperation::Remove(vec![alice_cred.id()]);
    assert!(HAS_NATIVES.load(storage).unwrap());
    assert!(update_credentials(api, storage, op.clone()).is_ok());
    // should update has natives flag to false
    assert!(!HAS_NATIVES.load(storage).unwrap());
    assert!(credential_count(storage) == 1);


    // reset credentials
    reset_credentials(storage, true, true).unwrap();
    save_credentials(api, storage, &env, &alice, &data).unwrap();

    // error: can't remove all three
    let op = UpdateOperation::Remove(vec![eth_cred.id(), passkey_cred.id(), alice_cred.id()]);
    assert!(update_credentials(api, storage,  op).is_err());


    // leave last one
    assert_eq!(credential_count(storage), 3);
    assert_eq!(VERIFYING_ID.load(storage).unwrap(), passkey_cred.id());
    assert!(HAS_NATIVES.load(storage).unwrap());

    let op = UpdateOperation::Remove(vec![eth_cred.id(), passkey_cred.id()]);
    assert!(update_credentials(api, storage, op).is_ok());
    assert!(HAS_NATIVES.load(storage).unwrap());
    assert_eq!(VERIFYING_ID.load(storage).unwrap(), alice_cred.id());
    assert_eq!(credential_count(storage), 1);

    //assert!(update_credentials(api, storage, &env, &alice.sender.to_string(), op.clone()).is_err());
    let op = UpdateOperation::Remove(vec![alice_cred.id()]);
    let res = update_credentials(api, storage, op).unwrap_err();
    assert!(res.to_string().contains("at least one credential"));
}



