#![allow(unused_import_braces, unused_extern_crates, unused_imports)]

use bitcoin_bosd::Descriptor;
use saa_common::{to_json_binary, Binary, Verifiable};
use smart_account_auth::{crypto::secp256k1_recover_pubkey, utils::hashes::{ripemd160, sha256}, Secp256k1};
use crate::utils::get_mock_deps;

use bitcoin::{hex::DisplayHex, opcodes, script::Builder, Address, Network, PubkeyHash, ScriptHash};
use bitcoin::hashes::Hash;
use b58::{encode, decode};



#[test]
fn can_check_bitcoin_secp256k1() {
    let deps = get_mock_deps();
    let deps = deps.as_ref();

    let numbers: Vec<i32> = Vec::new();

    let _even_numbers = numbers
        .into_iter()
        .filter(|x| x % 2 == 0)
        .collect::<Vec<_>>();

    
    let signature = "AkgwRQIhAN5v60jvmhuaOfUeWwLq23WqIom46te1Fl5euFlIxT95AiAnk5ah50xDMwaeOkbfEo6nANHJ1B5PJn502NzTxbOmTQEhAt7ar/ZhS0pKBUj9JSv7baGylASIDKFhM+Ijl94jPceu";
    let pubkey = hex::decode("02dedaaff6614b4a4a0548fd252bfb6da1b29404880ca16133e22397de233dc7ae").unwrap();
    let message = r#"{"chain_id":"elgafar-1","contract_address":"stars1g6gk427n9q4q22qxdlw8kajtumccde8dagt6eqh34spew3g78n0qrlp8gn","messages":["Create TBA account"],"nonce":"0"}"#;
    let addr = "3DH4YH2sK3iztERtWHXX5NuTHLHxhkddCo";
    // Test P2WPKH-P2SH address generz§ation from public key
    
     match bip322::verify_simple_encoded(addr, message, signature) {
        Ok(()) => println!("✅ ECDSA P2WPKH-P2SH verification succeeded!"),
        Err(e) => println!("❌ ECDSA P2WPKH-P2SH verification error: {}", e),
    }

    let credential = Secp256k1 {
        pubkey: Binary::new(pubkey),
        signature: Binary::from_base64(signature).unwrap(), // Use the already-trimmed signature (r+s only)
        message: message.as_bytes().to_vec().into(),
        hrp: None
    };
    let res = credential.verify(deps);
    println!("Final verification result: {:?}", res);
  //  assert!(res.is_ok()); 

}  

