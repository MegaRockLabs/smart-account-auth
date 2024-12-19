
#[cfg(test)]
mod tests {
    
    use cosmwasm_std::{coin, testing::mock_dependencies, CosmosMsg};
    use saa_common::{messages::MsgDataToSign, to_json_binary, Binary, Verifiable};
    use serde::{Deserialize, Serialize};
    use crate::passkey::{utils::base64_to_url, ClientData, PasskeyCredential};
    

    #[test]
    fn can_check_passkeys_simple() {

        let deps = mock_dependencies();
        let deps = deps.as_ref();

        let public_key = Binary::from_base64("BOirsl/nNsTWj3O5Qfseo9qZfs0uakJ6I97JLDZSbmeYk6nwkjIHM7UKp1DD/UnmurwUMFoqRIkO7sqsRFg8eUU=").unwrap();
        let authenticator_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==").unwrap();
        let signature = Binary::from_base64("z+0mm8OPyXrkeowj0P9COBElCZqmd7L6oJS2WDVarM6hoeIz0v4pnvQ8FAmUQthbwhfa03WoUUXVvzufNNw+nA==").unwrap();
        

        let credential = PasskeyCredential { 
            id: String::default(),
            pubkey: Some(public_key.clone()), 
            signature: signature.clone(), 
            authenticator_data: authenticator_data.clone(), 
            client_data: ClientData::new(
                "webauthn.get".into(),
                "MTIz".into(),
                "http://localhost:5173".into(),
                false,
                false
            ), 
            user_handle: None
        };

        let res = credential.verify_cosmwasm(deps.api);
        println!("Res: {:?}", res);
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
            nonce: "0".to_string()
        };

        let binary =  to_json_binary(&sign_data).unwrap();
        let challenge = base64_to_url(&binary.to_base64());

        let credential = PasskeyCredential { 
            id: String::default(),
            pubkey: Some(public_key.clone()), 
            signature: signature.clone(), 
            authenticator_data: authenticator_data.clone(), 
            client_data: ClientData::new(
                "webauthn.get".into(),
                challenge,
                "http://localhost:5173".into(),
                false,
                false
            ), 
            user_handle: None
        };
        let res = credential.verify_cosmwasm(deps.api);
        assert!(res.is_ok());
    }







    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum Action {
        Execute { msgs: Vec<CosmosMsg> },
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
                msgs: vec![CosmosMsg::Staking(cosmwasm_std::StakingMsg::Delegate { 
                    validator: "starsvaloper1q48vyzzz82kh9sn2zsslna3mhujx70s7yg5jzf".to_string(), 
                    amount: coin(1000000, "ustars")
                })] 
            }],
            nonce: "1".to_string()
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
                "webauthn.get".into(),
                challenge,
                "http://localhost:5173".into(),
                false,
                false
            ), 
            user_handle: None
        };
        let res = credential.verify_cosmwasm(deps.api);
        assert!(res.is_ok());
    }



}
