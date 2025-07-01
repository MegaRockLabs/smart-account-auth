use cosmwasm_std::Addr;
use saa_common::Verifiable;
use smart_account_auth::{CheckOption, EthTypedData, ReplayParams, ReplayProtection};

use crate::utils::{get_eth_signer, get_mock_deps, get_mock_env, SIGN_NONCE};

mod tests {

    use cosmwasm_std::testing::mock_dependencies;
    use saa_common::{Binary, Verifiable};
    use smart_account_auth::{EthPersonalSign, EthTypedData};

    use crate::utils::get_eth_signer;




    #[test]
    fn eth_personal_verifiable() {
        let deps = mock_dependencies();

        let message = r#"{"chain_id":"elgafar-1","contract_address":"stars1gjgfp9wps9c0r3uqhr0xxfgu02rnzcy6gngvwpm7a78j7ykfqquqr2fuj4","messages":["Create TBA account"],"nonce":"0"}"#;
        let base = "eyJjaGFpbl9pZCI6ImVsZ2FmYXItMSIsImNvbnRyYWN0X2FkZHJlc3MiOiJzdGFyczFnamdmcDl3cHM5YzByM3VxaHIweHhmZ3UwMnJuemN5NmduZ3Z3cG03YTc4ajd5a2ZxcXVxcjJmdWo0IiwibWVzc2FnZXMiOlsiQ3JlYXRlIFRCQSBhY2NvdW50Il0sIm5vbmNlIjoiMCJ9";
        let message = Binary::new(message.as_bytes().to_vec());
        assert!(message.to_base64() == base, "not euqal");

        let signature = Binary::from_base64(
            "a/lQuaTyhcTEeRA2XFTPxoDSIdS3yUUH1VSKOm2zz5EURfheGzzLgXea6QAalswOM2njnUzblqIGiOC0P+j2rhw="
        ).unwrap();

        let cred = EthPersonalSign {
            signer : get_eth_signer(),
            signature,
            message,
        };
        let res = cred.verify(deps.as_ref());
        println!("Res: {:?}", res);
        assert!(res.is_ok())
    }


    #[test]
    fn test_hash_nested_struct_array() {
        let json = serde_json::json!({
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "OrderComponents": [
              {
                "name": "offerer",
                "type": "address"
              },
              {
                "name": "zone",
                "type": "address"
              },
              {
                "name": "offer",
                "type": "OfferItem[]"
              },
              {
                "name": "startTime",
                "type": "uint256"
              },
              {
                "name": "endTime",
                "type": "uint256"
              },
              {
                "name": "zoneHash",
                "type": "bytes32"
              },
              {
                "name": "salt",
                "type": "uint256"
              },
              {
                "name": "conduitKey",
                "type": "bytes32"
              },
              {
                "name": "counter",
                "type": "uint256"
              }
            ],
            "OfferItem": [
              {
                "name": "token",
                "type": "address"
              }
            ],
            "ConsiderationItem": [
              {
                "name": "token",
                "type": "address"
              },
              {
                "name": "identifierOrCriteria",
                "type": "uint256"
              },
              {
                "name": "startAmount",
                "type": "uint256"
              },
              {
                "name": "endAmount",
                "type": "uint256"
              },
              {
                "name": "recipient",
                "type": "address"
              }
            ]
          },
          "primaryType": "OrderComponents",
          "domain": {
            "name": "Seaport",
            "version": "1.1",
            "chainId": "1",
            "verifyingContract": "0x00000000006c3852cbEf3e08E8dF289169EdE581"
          },
          "message": {
            "offerer": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "offer": [
              {
                "token": "0xA604060890923Ff400e8c6f5290461A83AEDACec"
              }
            ],
            "startTime": "1658645591",
            "endTime": "1659250386",
            "zone": "0x004C00500000aD104D7DBd00e3ae0A5C00560C00",
            "zoneHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "salt": "16178208897136618",
            "conduitKey": "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000",
            "totalOriginalConsiderationItems": "2",
            "counter": "0"
          },
          "signature": "",
          "signer": ""
        }
                );

        let typed_data: EthTypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712(None).unwrap();
        assert_eq!(
            "0b8aa9f3712df0034bc29fe5b24dd88cfdba02c7f499856ab24632e2969709a8",
            hex::encode(&hash[..])
        );
    }


    #[test]
    fn test_manual_replay_envelope() {
        let json = serde_json::json!({
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "Envelope": [
              {
                "name": "chain_id",
                "type": "string"
              },
              {
                "name": "contract_address",
                "type": "string"
              },
              {
                "name": "messages",
                "type": "string[]"
              },
              {
                "name": "nonce",
                "type": "string"
              }
            ],
          },
          "primaryType": "Envelope",
          "domain": {
            "name": "Token-Bound Accounts",
            "version": "1.1",
            "chainId": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000"
          },
          "message": {
            "chain_id": "constantine-3",
            "contract_address": "archway16qy02mwau05fn289h6mqm6qv4haqa6s2quwnjch0zch6a2yjr97qqv5ulg",
            "messages": ["Create TBA account"],
            "nonce": "0",
          },
          "signer": "0xac03048da6065e584d52007e22c69174cdf2b91a",
          "signature": "gJvZFFHWWy4RHirV50D1BfLZMZbJo+Oye5uKVFmLNnl0/kQEFOY8kngyEq3fuiMjYBgh1K7h5GrmyxqAZOmAYhs="
        });
        

        let deps = mock_dependencies();
        let cred: EthTypedData = serde_json::from_value(json).unwrap();
        println!("Cred: {:?}", cred.message);
        println!("Props: {:?}", cred.message.props);
        println!("Get props: {:?}", cred.message.get("chain_id"));

        let hash = cred.encode_eip712(None).unwrap();
        assert_eq!("11361aeafc7ea4ebb964e1213d59eba872c2488e5d737ed41a754d6a94b6b918", hex::encode(&hash[..]));

 
        let res = cred.verify(deps.as_ref());
        println!("Res: {:?}", res);
        assert!(res.is_ok());

        // "ETYa6vx+pOu5ZOEhPVnrqHLCSI5dc37UGnVNapS2uRg=";// 


    }
}




#[test]
fn eth_typed_daata_nft_acc_actions() {

  let json = serde_json::json!({
    "signer": get_eth_signer(),
    "signature": "s+Mm97zmBZpgVAQECscdQuKfqGwiCHGM2ju5U1M2rG9vu6WI7zjjVvQCw0PCt2e1N9S1e9Uha1QbCdcdSNY2dRs=",
    "message_property": "action",
    "types": {
        "EIP712Domain": [
            {
                "name": "name",
                "type": "string"
            },
            {
                "name": "version",
                "type": "string"
            },
            {
                "name": "chainId",
                "type": "uint256"
            },
            {
                "name": "verifyingContract",
                "type": "address"
            }
        ],
        "Coin": [
            {
                "name": "amount",
                "type": "uint256"
            },
            {
                "name": "denom",
                "type": "string"
            }
        ],
        "MintToken": [
            {
                "name": "minter",
                "type": "string"
            },
            {
                "name": "msg",
                "type": "string"
            }
        ],
        "BankSend": [
            {
                "name": "amount",
                "type": "Coin[]"
            },
            {
                "name": "to_address",
                "type": "string"
            }
        ],
        "Delegate": [
            {
                "name": "validator",
                "type": "string"
            },
            {
                "name": "amount",
                "type": "Coin"
            }
        ],
        "BankMsg": [
            {
                "name": "send",
                "type": "BankSend"
            }
        ],
        "StakingMsg": [
            {
                "name": "delegate",
                "type": "Delegate"
            }
        ],
        "CosmosMsg": [
            {
                "name": "bank",
                "type": "BankMsg"
            },
            {
                "name": "staking",
                "type": "StakingMsg"
            }
        ],
        "Execute": [
            {
                "name": "msgs",
                "type": "CosmosMsg[]"
            }
        ],
        "Transfer": [
            {
                "name": "collection",
                "type": "string"
            },
            {
                "name": "recipient",
                "type": "string"
            },
            {
                "name": "token_id",
                "type": "string"
            }
        ],
        "AccountAction": [
            {
                "name": "transfer_token",
                "type": "Transfer"
            },
            {
                "name": "execute",
                "type": "Execute"
            },
            {
                "name": "mint_token",
                "type": "MintToken"
            }
        ],
        "Prompt": [
            {
                "name": "actions",
                "type": "AccountAction[]"
            }
        ]
    },
    "primaryType": "Prompt",
    "domain": {
        "verifyingContract": "0x737eb72d8c0191736447f5bf06f0619ed647abee",
        "name": "Token-Bound Accounts",
        "version": "1.1",
        "chainId": "1"
    },
    "message": {
        "actions": [
            {
                "transfer_token": {
                    "collection": "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn",
                    "recipient": "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn",
                    "token_id": "1"
                }
            },
            {
                "execute": {
                    "msgs": [
                        {
                            "bank": {
                                "send": {
                                    "amount": [
                                        {
                                            "amount": "5000000",
                                            "denom": "ustars"
                                        }
                                    ],
                                    "to_address": "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn"
                                }
                            }
                        },
                        {
                            "staking": {
                                "delegate": {
                                    "amount": {
                                        "amount": "69000000",
                                        "denom": "uconst"
                                    },
                                    "validator": "archwayvaloper1qt0e4eyswes6qpply2pmk8v5qm88r2c962fnvk"
                                }
                            }
                        }
                    ]
                }
            },
            {
                "mint_token": {
                    "minter": "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn",
                    "msg": "eyAibWludCI6IHt9IH0="
                }
            }
        ]
      }
    }
  );
  let deps = get_mock_deps();
  let env = get_mock_env();
  let cred: EthTypedData = serde_json::from_value(json).unwrap();
  assert!(cred.validate().is_ok(), "Validation failed");
  assert!(cred.verify(deps.as_ref()).is_ok(), "Verification failed");
  assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Nothing)).is_ok(),);


}


#[test]
fn eth_typed_local_testing_chain() {
  let deps = get_mock_deps();
  let mut env = get_mock_env();
  env.block.chain_id = "testing".to_string();
  env.contract.address = Addr::unchecked("stars1wug8sewp6cedgkmrmvhl3lf3tulagm9hnvy8p0rppz9yjw0g4wtqmpd9x3");

  let json = serde_json::json!({
    "types": {
      "EIP712Domain": [
        { "name": "name", "type": "string" },
        { "name": "version", "type": "string" },
        { "name": "chainId", "type": "uint256" },
        { "name": "verifyingContract", "type": "address" }
      ],
      "Transfer": [
        { "name": "collection", "type": "string" },
        { "name": "recipient", "type": "string" },
        { "name": "token_id", "type": "string" }
      ],
      "AccountAction": [
        { "name": "transfer_token", "type": "Transfer" }
      ]
    },
    "primaryType": "AccountAction",
    "domain": {
      "chainId": "0",
      "name": "Token-Bound Accounts",
      "verifyingContract": "0x518526d38c3242f316c622fd464c7b8970dd1250",
      "version": "1.1"
    },
    "message": {
      "transfer_token": {
        "collection": "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn",
        "recipient": "stars1wgesz5jrx3uvt29a9awkafy4p06rutxv2xdnqperde4tmzx4n2yq95mumn",
        "token_id": "1"
      }
    },
    "signer": "0xac03048da6065e584d52007e22c69174cdf2b91a",
    "signature": "fRKr9rJAX7EGar40a9PYYfeEY14l2M8NXutilC8K2b5zMD5y+3Jl//yKEyfmaXd5CIBuM0XTqk6Lji2cO4WKnRs="
  });

  let cred: EthTypedData = serde_json::from_value(json).unwrap();

  assert!(cred.validate().is_ok(), "Validation failed");
  assert!(cred.verify(deps.as_ref()).is_ok(), "Verification failed");
  assert!(cred.protect_reply(&env, ReplayParams::new(SIGN_NONCE, CheckOption::Nothing)).is_ok(),);


}