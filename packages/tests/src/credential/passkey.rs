use crate::types::{Coin, CosmosMsg, StakingMsg};
use cosmwasm_std::testing::mock_dependencies;
use saa_common::{to_json_binary, Binary, Verifiable};
use smart_account_auth::{utils::passkey::base64_to_url,
    types::{ClientDataOtherKeys, ClientData},
    msgs::MsgDataToSign, PasskeyCredential,
};


#[saa_schema::saa_type]
enum Action {
    Execute { msgs: Vec<CosmosMsg> },
}


const OTHER_KEY : &str = "do not compare clientDataJSON against a template. See https://goo.gl/yabPex";




#[test]
fn can_check_passkeys_simple() {

    let deps = mock_dependencies();
    let deps = deps.as_ref();
    let pubkey = Some(
        Binary::from_base64(
            "BOirsl/nNsTWj3O5Qfseo9qZfs0uakJ6I97JLDZSbmeYk6nwkjIHM7UKp1DD/UnmurwUMFoqRIkO7sqsRFg8eUU="
        ).unwrap()
    );
    let signature = Binary::from_base64("z+0mm8OPyXrkeowj0P9COBElCZqmd7L6oJS2WDVarM6hoeIz0v4pnvQ8FAmUQthbwhfa03WoUUXVvzufNNw+nA==").unwrap();
    let authenticator_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==").unwrap();
    

    let credential = PasskeyCredential { 
        id: String::default(),
        pubkey, 
        signature, 
        authenticator_data, 
        client_data: ClientData::new(
             "MTIz",
             "http://localhost:5173",
            false,
            None
        ), 
        user_handle: None
    };

    let res = credential.verify_cosmwasm(deps.api);
    //println!("Res: {:?}", res);
    assert!(res.is_ok());

}




#[test]
fn can_check_passkeys_data_string() {
    let deps = mock_dependencies();
    let deps = deps.as_ref();

    let public_key = Binary::from_base64("BCY0yONLF00/EUnwdtYaJI4oJqMGS7YT5h4iMLmaG0hJoJLiu/gkUWVfEEM4uo9c9yAgCoMF8A1vzxvaLW8mVjw=").unwrap();
    let authenticator_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==").unwrap();
    let signature = Binary::from_base64("769aJAhtP9QZNW/j5iI8KN9joewE/CFN0dRWxfL/cR2TWDPiLo0x4UxzOSF6VQUws8PW2T7YE45BRSMFUeNeNA==").unwrap();

    let sign_data =  MsgDataToSign::<String> {
        chain_id: "pion-1".to_string(),
        contract_address: "neutron1uf26dql0t895fzltzp3q7t5g7q77e6e8d790jf7lp78kdwcyahlqe38qg5".to_string(),
        messages: vec![String::from("Create Proxy Account")],
        nonce: 0u64.into()
    };

    let binary =  to_json_binary(&sign_data).unwrap();
    let challenge = base64_to_url(&binary.to_base64());

    let credential = PasskeyCredential { 
        id: String::default(),
        pubkey: Some(public_key.clone()), 
        signature: signature.clone(), 
        authenticator_data: authenticator_data.clone(), 
        client_data: ClientData::new(
            challenge,
            "http://localhost:5173",
            false,
            None
        ), 
        user_handle: None
    };
    let res = credential.verify_cosmwasm(deps.api);
    assert!(res.is_ok());
}




#[test]
fn can_check_passkeys_data_actions() {
    let deps = mock_dependencies();
    let deps = deps.as_ref();

    let public_key = Binary::from_base64("BOirsl/nNsTWj3O5Qfseo9qZfs0uakJ6I97JLDZSbmeYk6nwkjIHM7UKp1DD/UnmurwUMFoqRIkO7sqsRFg8eUU=").unwrap();
    let authenticator_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==").unwrap();
    let signature = Binary::from_base64("6EWu7ddbiHYJwTEVJ4ekwslcEyyX1l4smaLhuEqi1fkUChmE3ZjNPZfEO6OKEQU1khyHnbscG+ISo36P22+nyA==").unwrap();

    let sign_data =  MsgDataToSign::<Action> {
        chain_id: "elgafar-1".to_string(),
        contract_address: "stars156t98r39hf3yr8n76e24asywy45y4lthwfs5349q0ucp28wqp9lsquujva".to_string(),
        messages: vec![Action::Execute { 
            msgs: vec![CosmosMsg::Staking(StakingMsg::Delegate { 
                validator: "starsvaloper1q48vyzzz82kh9sn2zsslna3mhujx70s7yg5jzf".to_string(), 
                amount: Coin {
                    denom: "ustars".to_string(), 
                    amount: 1000000u128.into()
                }
            })] 
        }],
        nonce: 1u64.into()
    };
    
    let binary =  to_json_binary(&sign_data).unwrap();
    let challenge = base64_to_url(&binary.to_base64());
    
    let json_str = r#"{"chain_id":"elgafar-1","contract_address":"stars156t98r39hf3yr8n76e24asywy45y4lthwfs5349q0ucp28wqp9lsquujva","messages":[{"execute":{"msgs":[{"staking":{"delegate":{"validator":"starsvaloper1q48vyzzz82kh9sn2zsslna3mhujx70s7yg5jzf","amount":{"denom":"ustars","amount":"1000000"}}}}]}}],"nonce":"1"}"#;
    let encoded_string = base64_url::encode(&json_str);
    assert_eq!(challenge, encoded_string);

    let credential = PasskeyCredential { 
        id: String::default(),
        pubkey: Some(public_key.clone()), 
        signature: signature.clone(), 
        authenticator_data: authenticator_data.clone(), 
        client_data: ClientData::new(
            challenge,
            "http://localhost:5173",
            false,
            None
        ), 
        user_handle: None
    };
    let res = credential.verify_cosmwasm(deps.api);
    assert!(res.is_ok());
}



#[test]
fn pass_verification_with_other_keys() {
    let deps = mock_dependencies();
    let deps = deps.as_ref();

    let public_key = Binary::from_base64("BO24TMuQ4FKvLq3/H8+IkIdDPzT2vlnt78sDOeZfOEIQ3I1J/QjdLEC8LwWD7shur5D119j9nQw61cfcYobLiIA=").unwrap();
    let authenticator_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==").unwrap();
    let signature = Binary::from_base64("U7C9wBtbEKh1V1GJccbFmLzF9SrR+rArjbKgVUt1EKWDMCm+0oPpRH1/0KN8WlKKIov3p/nm12JpzU6pKQAwDw==").unwrap();

    let sign_data =  MsgDataToSign::<String> {
        chain_id: "elgafar-1".to_string(),
        contract_address: "stars1fjhqywml8vx26n58s05yy4evtg9h9xjkvya0rtlqkecvkpdysemq2hqy8m".to_string(),
        messages: vec![String::from("Create TBA account")],
        nonce: 0u64.into()
    };
    
    let binary =  to_json_binary(&sign_data).unwrap();
    let challenge = base64_to_url(&binary.to_base64());


    let credential = PasskeyCredential { 
        id: String::default(),
        pubkey: Some(public_key.clone()), 
        signature: signature.clone(), 
        authenticator_data: authenticator_data.clone(), 
        client_data: ClientData::new(
            challenge.clone(),
            "http://localhost:5173",
            false,
            Some(
                ClientDataOtherKeys::new(Some(OTHER_KEY.to_string()))
            )
        ), 
        user_handle: None
    };
    let res = credential.verify_cosmwasm(deps.api);
    assert!(res.is_ok());


    let credential = PasskeyCredential { 
        id: String::default(),
        pubkey: Some(public_key.clone()), 
        signature: signature.clone(), 
        authenticator_data: authenticator_data.clone(), 
        client_data: ClientData::new(
            challenge,
            "http://localhost:5173",
            false,
            None
        ), 
        user_handle: None
    };
    let res = credential.verify_cosmwasm(deps.api);
    assert!(res.is_err());

}