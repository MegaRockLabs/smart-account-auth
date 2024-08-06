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

        let public_key = Binary::from_base64("BGDRdC9Ynea9vlpLxFZmEGL1cYpxGgzRvEMzlugVfmYOyACjQ5wHA8DNuCR4GI/Sfj6OkVNlyvuwyfkeOPavcG8=").unwrap();
        let auth_data  = Binary::from_base64("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==").unwrap();
        let signature = Binary::from_base64("6dMQf0mPwkFBPuAElErBTi3SbqhWKRVxZVix/YwcbxxPLEGifo+KITlWmY4CX/ZoVJllFmW03DYKWwNo+7lIOw==").unwrap();

        let credential = PasskeyCredential { 
            id: String::default(),
            pubkey: Some(public_key), 
            signature, 
            authenticator_data: auth_data, 
            client_data: ClientData {
                ty: "webauthn.get".to_string(),
                challenge: "Q3JlYXRpbmcgVEJBIGFjY291bnQ".into(),
                cross_origin: false,
                origin: "http://localhost:5173".into(),
            }, 
            user_handle: None
        };

        let res = credential.verified_cosmwasm(deps.api, &env, &Some(info));

        println!("Res: {:?}", res);
        assert!(res.is_ok());
    }


}
