mod tests {
    use std::str::FromStr;

    use cosmwasm_std::{testing::{mock_dependencies, mock_env}, Uint256};
    use saa_common::{Binary, Verifiable};

    use crate::evm::EvmCredential;


    #[test]
    fn verifying_ethereum_signature() {
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

        let cred  =  EvmCredential  {
            message : Binary(message.as_bytes().to_vec()),
            signer : address.to_string(),
            signature : Binary(sig),
        };

        assert!(cred.verified_cosmwasm(deps.as_ref().api, &env, &None).is_ok())
    }
}