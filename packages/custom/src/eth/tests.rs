mod tests {
    use std::str::FromStr;

    use cosmwasm_std::{testing::{mock_dependencies, mock_env}, Uint256};
    use saa_common::{to_json_binary, Binary, Verifiable};

    use crate::eth::EthPersonalSign;

/* 
    #[test]
    fn evm_cred_verifiable() {
        let deps = mock_dependencies();
        let env = mock_env();

        let message = "hello world";
        let address = "0x63F9725f107358c9115BC9d86c72dD5823E9B1E6";

        let r = Uint256::from_str("49684349367057865656909429001867135922228948097036637749682965078859417767352").unwrap();
        let s = Uint256::from_str("26715700564957864553985478426289223220394026033170102795835907481710471636815").unwrap();
        let v = 28u8;

        let mut sig = vec![];
        sig.extend(r.to_be_bytes());
        sig.extend(s.to_be_bytes());
        sig.push(v);
        assert_eq!(sig.len(), 65);

        let hex = hex::encode(&sig);
        let bin = Binary(message.as_bytes().to_vec());

        let msgs = vec![
            bin.clone(),
            to_json_binary(&message).unwrap(),  
            Binary(hex.as_bytes().to_vec()),
            to_json_binary(&hex).unwrap(),
            Binary(message.as_bytes().to_vec()),
            Binary(hex::encode(message).as_bytes().to_vec()),
            to_json_binary(&hex::encode(message)).unwrap(),
        ];

        for message in msgs {
            let cred = EthPersonalSign {
                signer : address.to_string(),
                signature: Binary(sig.clone()),
                message,
            };
            let res = cred.verify_cosmwasm(deps.as_ref().api, &env);
            println!("Res: {:?}", res);
        }

        let cred  =  EthPersonalSign  {
            message : Binary(message.as_bytes().to_vec()),
            signer : address.to_string(),
            signature : Binary(sig),
        };

        #[cfg(feature = "native")]
        assert!(cred.verify().is_ok());

        #[cfg(feature = "cosmwasm")]
        assert!(cred.verify_cosmwasm(deps.as_ref().api, &env).is_ok())
    }
 */
    #[test]
    fn eth_personal_verifiable() {
        let deps = mock_dependencies();
        let env = mock_env();

        
        //let message = "{"chain_id":"elgafar-1","contract_address":"stars1s37ajgt66kxpjtwvzy3wlk6qkrltt69dxee9x973st8f6sejawcsxpputg","messages":["Create TBA account"],"nonce":"0"}";
        // escaped version of the above message
        let message = r#"{"chain_id":"elgafar-1","contract_address":"stars1s37ajgt66kxpjtwvzy3wlk6qkrltt69dxee9x973st8f6sejawcsxpputg","messages":["Create TBA account"],"nonce":"0"}"#;
        let address = "0xac03048da6065e584d52007e22c69174cdf2b91a";
        let base = "eyJjaGFpbl9pZCI6ImVsZ2FmYXItMSIsImNvbnRyYWN0X2FkZHJlc3MiOiJzdGFyczFzMzdhamd0NjZreHBqdHd2enkzd2xrNnFrcmx0dDY5ZHhlZTl4OTczc3Q4ZjZzZWphd2NzeHBwdXRnIiwibWVzc2FnZXMiOlsiQ3JlYXRlIFRCQSBhY2NvdW50Il0sIm5vbmNlIjoiMCJ9";
        let message = Binary(message.as_bytes().to_vec());
        assert!(message.to_base64() == base, "not euqal");



        //let message = top;

        let signature = Binary::from_base64(
            "kqQidnTi0EdFWOIJjbD6bbjagNqdLX3jjBgVGCGZGFNVTN1J/fdmmZxJ+vq0oRIKQV4BnLLSsUMFCJ90z7R5Ehs="
        ).unwrap();


        let cred = EthPersonalSign {
            signer : address.to_string(),
            signature: signature.clone(),
            message,
        };
        let res = cred.verify_cosmwasm(deps.as_ref().api, &env);
        println!("Res: {:?}", res);
        assert!(res.is_ok())
    }
}