mod tests {

    use cosmwasm_std::testing::mock_dependencies;
    use saa_common::{Binary, Verifiable};
    use smart_account_auth::EthPersonalSign;


    #[test]
    fn eth_personal_verifiable() {
        let deps = mock_dependencies();

        let message = r#"{"chain_id":"elgafar-1","contract_address":"stars1gjgfp9wps9c0r3uqhr0xxfgu02rnzcy6gngvwpm7a78j7ykfqquqr2fuj4","messages":["Create TBA account"],"nonce":"0"}"#;
        let address = "0xac03048da6065e584d52007e22c69174cdf2b91a";
        let base = "eyJjaGFpbl9pZCI6ImVsZ2FmYXItMSIsImNvbnRyYWN0X2FkZHJlc3MiOiJzdGFyczFnamdmcDl3cHM5YzByM3VxaHIweHhmZ3UwMnJuemN5NmduZ3Z3cG03YTc4ajd5a2ZxcXVxcjJmdWo0IiwibWVzc2FnZXMiOlsiQ3JlYXRlIFRCQSBhY2NvdW50Il0sIm5vbmNlIjoiMCJ9";
        let message = Binary::new(message.as_bytes().to_vec());
        assert!(message.to_base64() == base, "not euqal");

        let signature = Binary::from_base64(
            "a/lQuaTyhcTEeRA2XFTPxoDSIdS3yUUH1VSKOm2zz5EURfheGzzLgXea6QAalswOM2njnUzblqIGiOC0P+j2rhw="
        ).unwrap();

        let cred = EthPersonalSign {
            signer : address.to_string(),
            signature: signature.clone(),
            message,
        };
        let res = cred.verify_cosmwasm(deps.as_ref().api);
        println!("Res: {:?}", res);
        assert!(res.is_ok())
    }
}