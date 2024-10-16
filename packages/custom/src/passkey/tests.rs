#[cfg(test)]
mod tests {
    
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use saa_common::{Binary, Verifiable};
    use crate::passkey::{ClientData, PasskeyCredential};


    #[test]
    fn can_check_passkeys() {

        let deps = mock_dependencies();
        let deps = deps.as_ref();
        let env = mock_env();
        let info = mock_info("test", &vec![]);

        let public_key = Binary::from_base64("BI0JR98MB4w+dSphFbtyfcDqoiZu+DPrCqXg+C+S39hfKfFBLOQe/zDGOII6DG2YDJDG3d9r3bwxD1V386EIDr8=").unwrap();
        let authenticator_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==").unwrap();
        let signature = Binary::from_base64("nHulr6uSx6kd+qAsHSOmTb7o22wfWfJuJsXyVvUfjvkAxk3B/KmEboJKWnhuMZcGWWlkDcgDiYpKx4amx4HRBw==").unwrap();

        let credential = PasskeyCredential { 
            id: String::default(),
            pubkey: Some(public_key), 
            signature, 
            authenticator_data, 
            client_data: ClientData {
                ty: "webauthn.get".to_string(),
                challenge: "Q3JlYXRlIFRCQSBhY2NvdW50dA".into(),
                origin: "http://localhost:5173".into(),
                cross_origin: false,
            }, 
            user_handle: None
        };

        let res = credential.verified_cosmwasm(deps.api, &env, &Some(info));

        println!("Res: {:?}", res);
        assert!(res.is_ok());
    }



    #[test]
    fn can_check_passkeys_2() {

        let deps = mock_dependencies();
        let deps = deps.as_ref();
        let env = mock_env();
        let info = mock_info("test", &vec![]);

        let public_key = Binary::from_base64("BGDRdC9Ynea9vlpLxFZmEGL1cYpxGgzRvEMzlugVfmYOyACjQ5wHA8DNuCR4GI/Sfj6OkVNlyvuwyfkeOPavcG8=").unwrap();
        let authenticator_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==").unwrap();
        let signature = Binary::from_base64("6dMQf0mPwkFBPuAElErBTi3SbqhWKRVxZVix/YwcbxxPLEGifo+KITlWmY4CX/ZoVJllFmW03DYKWwNo+7lIOw==").unwrap();

        let credential = PasskeyCredential { 
            id: String::default(),
            pubkey: Some(public_key), 
            signature, 
            authenticator_data, 
            client_data: ClientData {
                ty: "webauthn.get".to_string(),
                challenge: "Q3JlYXRpbmcgVEJBIGFjY291bnQ".into(),
                origin: "http://localhost:5173".into(),
                cross_origin: false,
            }, 
            user_handle: None
        };

        let res = credential.verified_cosmwasm(deps.api, &env, &Some(info));

        println!("Res: {:?}", res);
        assert!(res.is_ok());
    }



}
