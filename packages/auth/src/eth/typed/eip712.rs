// use saa_schema::saa_type;
// use saa_common::{Binary, Uint64};
// use saa_crypto::hashes::keccak256;
// use ethabi::{encode, ethereum_types::{H160, U256}, Token};
// use serde::{Deserialize, Serialize};




// #[saa_type(no_deny)]
// pub struct Eip712DomainType {
//     pub name: String,
//     #[serde(rename = "type")]
//     pub r#type: String,
// }


// /// Taken from [ethers-rs](https://github.com/gakonst/ethers-rs/blob/6e2ff0ef8af8c0ee3c21b7e1960f8c025bcd5588/ethers-core/src/types/transaction/eip712.rs#L107)
// /// Eip712 Domain attributes used in determining the domain separator;
// /// Unused fields are left out of the struct type.
// ///
// /// Protocol designers only need to include the fields that make sense for their signing domain.
// /// Unused fields are left out of the struct type.
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct EIP712Domain {
//     ///  The user readable name of signing domain, i.e. the name of the DApp or the protocol.
//     #[serde(default, skip_serializing_if = "Option::is_none")]
//     pub name: Option<String>,

//     /// The current major version of the signing domain. Signatures from different versions are not
//     /// compatible.
//     #[serde(default, skip_serializing_if = "Option::is_none")]
//     pub version: Option<String>,

//     /// The EIP-155 chain id. The user-agent should refuse signing if it does not match the
//     /// currently active chain.
//     #[serde(default, skip_serializing_if = "Option::is_none")]
//     pub chain_id: Option<Uint64>,

//     /// The address of the contract that will verify the signature.
//     #[serde(default, skip_serializing_if = "Option::is_none")]
//     pub verifying_contract: Option<String>,

//     /// A disambiguating salt for the protocol. This can be used as a domain separator of last
//     /// resort.
//     #[serde(default, skip_serializing_if = "Option::is_none")]
//     pub salt: Option<Binary>,
// }





// impl EIP712Domain {

//     pub fn separator(&self) -> [u8; 32] {
//         // full name is `EIP712Domain(string name,string version,uint256 chainId,address
//         // verifyingContract,bytes32 salt)`
//         let mut ty = "EIP712Domain(".to_string();

//         let mut tokens = Vec::new();
//         let mut needs_comma = false;
//         if let Some(ref name) = self.name {
//             ty += "string name";
//             tokens.push(Token::Uint(U256::from(keccak256(name.as_bytes()))));
//             needs_comma = true;
//         }

//         if let Some(ref version) = self.version {
//             if needs_comma {
//                 ty.push(',');
//             }
//             ty += "string version";
//             tokens.push(Token::Uint(U256::from(keccak256(version.as_bytes()))));
//             needs_comma = true;
//         }

//         if let Some(chain_id) = self.chain_id {
//             if needs_comma {
//                 ty.push(',');
//             }
//             ty += "uint256 chainId";
//             tokens.push(Token::Uint(U256::from(chain_id.u64())));
//             needs_comma = true;
//         }

//         if let Some(ref verifying_contract) = self.verifying_contract {
//             if needs_comma {
//                 ty.push(',');
//             }
//             ty += "address verifyingContract";
//             let bytes : [u8; 20] = verifying_contract.as_bytes()
//                 .try_into()
//                 .expect("verifying_contract should be 20 bytes long");
//             tokens.push(Token::Address(H160::from(bytes)));
//             needs_comma = true;
//         }

//         if let Some(ref salt) = self.salt {
//             if needs_comma {
//                 ty.push(',');
//             }
//             ty += "bytes32 salt";
//             tokens.push(Token::Uint(U256::from(salt.as_slice())));
//         }

//         ty.push(')');

//         tokens.insert(0, Token::Uint(U256::from(keccak256(ty.as_bytes()))));

//         keccak256(&encode(tokens.as_slice()))
//     }
// }
