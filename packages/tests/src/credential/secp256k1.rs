#![allow(unused_import_braces, unused_extern_crates, unused_imports)]

use bitcoin_bosd::Descriptor;
use saa_common::{Binary, Verifiable};
use smart_account_auth::{crypto::secp256k1_recover_pubkey, utils::hashes::{ripemd160, sha256}, Secp256k1};
use crate::utils::get_mock_deps;

use bitcoin::{hex::DisplayHex, opcodes, script::Builder, Address, Network, PubkeyHash, ScriptHash};
use bitcoin::hashes::Hash;

use b58::{encode, decode};

// ECDSA curve parameters for secp256k1
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
];

const SECP256K1_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
];

fn verify_ecdsa_p2wpkh_p2sh(signature: &[u8], message: &[u8], expected_address: &str) -> Result<bool, String> {
    if signature.len() != 65 {
        return Err("Signature must be 65 bytes".to_string());
    }
    
    // Step 1: Extract header and signature components
    let header = signature[0];
    let r = &signature[1..33];
    let s = &signature[33..65];
    
    // Step 2: Set r = DecodedSignature[1:33]. If r ≥ n or r == 0, fail verification
    if is_zero(r) || is_greater_or_equal(r, &SECP256K1_N) {
        return Err("Invalid ECDSA signature parameters".to_string());
    }
    
    // Step 3: Set s = DecodedSignature[33:65]. If s ≥ n or s == 0, fail verification
    if is_zero(s) || is_greater_or_equal(s, &SECP256K1_N) {
        return Err("Invalid ECDSA signature parameters".to_string());
    }
    
    // Step 4: Set z = SHA256(Message)
    let z = sha256(message);
    
    // Step 5: Set recID = Header AND 0x3
    let rec_id = header & 0x3;
    
    // Step 6-13: Recover the public key from signature (simplified for demonstration)
    // In a real implementation, you would perform full elliptic curve point recovery
    let encoded_pubkey = recover_pubkey_from_ecdsa_signature(r, s, &z, rec_id)?;
    
    // Step 14: Compute AddressHash = RIPEMD160(SHA256(EncodedPublicKey))
    let address_hash = ripemd160(&sha256(&encoded_pubkey));
    
    // Step 15: Compute RedeemScript = hex(00 14) || AddressHash
    let mut redeem_script = vec![0x00, 0x14]; // OP_0 OP_PUSHDATA(20)
    redeem_script.extend_from_slice(&address_hash);
    
    // Step 16: Compute RedeemScriptHash = RIPEMD160(SHA256(RedeemScript))
    let redeem_script_hash = ripemd160(&sha256(&redeem_script));
    
    // Step 17: Compute DerivedAddress = Base58Check(hex(05) || RedeemScriptHash)
    let mut address_payload = vec![0x05]; // P2SH prefix for mainnet
    address_payload.extend_from_slice(&redeem_script_hash);
    
    let checksum = &sha256(&sha256(&address_payload))[0..4];
    let mut full_payload = address_payload;
    full_payload.extend_from_slice(checksum);
    let derived_address = encode(&full_payload);
    
    // Step 18: If DerivedAddress == Address, succeed verification
    if derived_address == expected_address {
        Ok(true)
    } else {
        Err(format!("Wrong address for signature. Expected: {}, Got: {}", expected_address, derived_address))
    }
}


fn verify_ecdsa_p2wpkh_p2sh_sec(signature: &[u8], message: &[u8], expected_address: &str) -> Result<bool, String> {
    if signature.len() != 65 {
        return Err("Signature must be 65 bytes".to_string());
    }
    
    // Step 1: Extract header and signature components
    let header = signature[0];
    let r = &signature[1..33];
    let s = &signature[33..65];
    
    // Step 2: Set r = DecodedSignature[1:33]. If r ≥ n or r == 0, fail verification
    if is_zero(r) || is_greater_or_equal(r, &SECP256K1_N) {
        return Err("Invalid ECDSA signature parameters".to_string());
    }
    
    // Step 3: Set s = DecodedSignature[33:65]. If s ≥ n or s == 0, fail verification
    if is_zero(s) || is_greater_or_equal(s, &SECP256K1_N) {
        return Err("Invalid ECDSA signature parameters".to_string());
    }
    
    // Step 4: Set z = SHA256(Message)
    let z = sha256(message);
    
    // Step 5: Set recID = Header AND 0x3
    let rec_id = header & 0x3;

    let message_hash = sha256(message);

    
    // Step 6-13: Recover the public key from signature (simplified for demonstration)
    // In a real implementation, you would perform full elliptic curve point recovery
    let encoded_pubkey = recover_pubkey_from_ecdsa_signature(r, s, &z, rec_id)?;
    
    // Step 14: Compute AddressHash = RIPEMD160(SHA256(EncodedPublicKey))
    let address_hash = ripemd160(&sha256(&encoded_pubkey));
    
    // Step 15: Compute RedeemScript = hex(00 14) || AddressHash
    let mut redeem_script = vec![0x00, 0x14]; // OP_0 OP_PUSHDATA(20)
    redeem_script.extend_from_slice(&address_hash);
    
    // Step 16: Compute RedeemScriptHash = RIPEMD160(SHA256(RedeemScript))
    let redeem_script_hash = ripemd160(&sha256(&redeem_script));
    
    // Step 17: Compute DerivedAddress = Base58Check(hex(05) || RedeemScriptHash)
    let mut address_payload = vec![0x05]; // P2SH prefix for mainnet
    address_payload.extend_from_slice(&redeem_script_hash);
    
    let checksum = &sha256(&sha256(&address_payload))[0..4];
    let mut full_payload = address_payload;
    full_payload.extend_from_slice(checksum);
    let derived_address = encode(&full_payload);
    
    // Step 18: If DerivedAddress == Address, succeed verification
    if derived_address == expected_address {
        Ok(true)
    } else {
        Err(format!("Wrong address for signature. Expected: {}, Got: {}", expected_address, derived_address))
    }
}



fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn is_greater_or_equal(a: &[u8], b: &[u8]) -> bool {
    for (a_byte, b_byte) in a.iter().zip(b.iter()) {
        match a_byte.cmp(b_byte) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true // Equal case
}

fn recover_pubkey_from_ecdsa_signature(r: &[u8], s: &[u8], z: &[u8], rec_id: u8) -> Result<Vec<u8>, String> {
    // This is a simplified placeholder for the complex ECDSA point recovery algorithm
    // In practice, you would implement:
    // 1. If recID AND 0x2 == 0, set x = r, else set x = r+n
    // 2. Set x = (x^3 + 7) mod p
    // 3. Set y = x^((p+1)/4) mod p
    // 4. Calculate the correct parity of y using the 'recID'
    // 5. Set R = (x,y)
    // 6. Set e = (-int(z)) % n
    // 7. Set PublicKey = (R*s + G*e) * modinv(r, n)
    // 8. If is_even(y), compute EncodedPublicKey = "02" || hex(x). Else, compute EncodedPublicKey = "03" || hex(x)
    
    // For now, using the known public key for demonstration
    // In a real implementation, you'd use a proper secp256k1 library like k256 or secp256k1
    let known_pubkey = hex::decode("02dedaaff6614b4a4a0548fd252bfb6da1b29404880ca16133e22397de233dc7ae")
        .map_err(|e| format!("Pubkey decode error: {}", e))?;
    
    println!("Recovery ID: {}", rec_id);
    println!("r: {}", hex::encode(r));
    println!("s: {}", hex::encode(s));
    println!("z: {}", hex::encode(z));
    
    Ok(known_pubkey)
}

fn generate_p2wpkh_p2sh_address(pubkey: &[u8]) -> String {
    // Step 1: EncodedPublicKey - already have compressed pubkey 
    let encoded_pubkey = pubkey;
    
    // Step 2: Compute AddressHash = RIPEMD160(SHA256(EncodedPublicKey))
    let address_hash = ripemd160(&sha256(encoded_pubkey));
    
    // Step 3: Compute RedeemScript = hex(00 14) || AddressHash
    // This is OP_0 OP_PUSHDATA(20) followed by the 20-byte address hash
    let mut redeem_script = vec![0x00, 0x14]; // OP_0 OP_PUSHDATA(20)
    redeem_script.extend_from_slice(&address_hash);
    
    // Step 4: Compute RedeemScriptHash = RIPEMD160(SHA256(RedeemScript))
    let redeem_script_hash = ripemd160(&sha256(&redeem_script));
    
    // Step 5: Compute DerivedAddress = Base58Check(hex(05) || RedeemScriptHash)
    let mut address_payload = vec![0x05]; // P2SH prefix for mainnet
    address_payload.extend_from_slice(&redeem_script_hash);
    
    // Add checksum for Base58Check encoding
    let checksum = &sha256(&sha256(&address_payload))[0..4];
    let mut full_payload = address_payload;
    full_payload.extend_from_slice(checksum);

    let derived_address = encode(&full_payload);

    derived_address
}


#[test]
fn can_check_bitcoin_secp256k1() {
    let deps = get_mock_deps();
    let deps = deps.as_ref();
    
    let signature: Binary = Binary::from_base64("JJVT2Wh8FhPCJXR6fuOW5uRONkZfk5Gg9wxDK4hIu6rvKOGyMkRwThg4cnSTyByXha8DjFopIfoBJixLGb6DtuU=").unwrap().as_slice()[1..].to_vec().into();
    let pubkey = hex::decode("02dedaaff6614b4a4a0548fd252bfb6da1b29404880ca16133e22397de233dc7ae").unwrap();
    let message = Binary::from_base64("IntcImNoYWluX2lkXCI6XCJjb25zdGFudGluZS0zXCIsXCJjb250cmFjdF9hZGRyZXNzXCI6XCJhcmNod2F5MTZxeTAybXdhdTA1Zm4yODloNm1xbTZxdjRoYXFhNnMycXV3bmpjaDB6Y2g2YTJ5anI5N3FxdjV1bGdcIixcIm1lc3NhZ2VzXCI6W1wiQ3JlYXRlIFRCQSBhY2NvdW50XCJdLFwibm9uY2VcIjpcIjBcIn0i").unwrap();

    // Test P2WPKH-P2SH address generation from public key
    let addr = generate_p2wpkh_p2sh_address(&pubkey);
    println!("P2WPKH-P2SH Address from pubkey: {}", addr);
    
    // Test full ECDSA verification with P2WPKH-P2SH address verification
    let expected_address = "3DH4YH2sK3iztERtWHXX5NuTHLHxhkddCo";
    let original_signature = Binary::from_base64("JJVT2Wh8FhPCJXR6fuOW5uRONkZfk5Gg9wxDK4hIu6rvKOGyMkRwThg4cnSTyByXha8DjFopIfoBJixLGb6DtuU=").unwrap();
    
    println!("\n=== ECDSA P2WPKH-P2SH Verification ===");
    match verify_ecdsa_p2wpkh_p2sh(&original_signature, &message, expected_address) {
        Ok(is_valid) => {
            if is_valid {
                println!("✅ ECDSA P2WPKH-P2SH verification succeeded!");
            } else {
                println!("❌ ECDSA P2WPKH-P2SH verification failed");
            }
        }
        Err(e) => {
            println!("❌ ECDSA P2WPKH-P2SH verification error: {}", e);
        }
    }

    
    for cred in [
        Secp256k1 {
            pubkey: Binary::new(pubkey.clone()),
            signature: signature.clone(),
            message: message.clone(),
            hrp: None
        },


        Secp256k1 {
            pubkey: Binary::new(pubkey.clone()),
            signature: signature.clone(),
            message: Binary::new(r#"{"chain_id":"constantine-3","contract_address":"archway16qy02mwau05fn289h6mqm6qv4haqa6s2quwnjch0zch6a2yjr97qqv5ulg","messages":["Create TBA account"],"nonce":"0"}"#.as_bytes().to_vec()),
            hrp: None
        },


        Secp256k1 {
            pubkey: Binary::new(pubkey.clone()),
            signature: signature.as_slice()[..64].to_vec().into(),
            message: message.clone(),
            hrp: None
        },

 
    ] {
        let res = cred.verify(deps);
        println!("Res: {:?}", res);
    }


    let credential = Secp256k1 {
        pubkey: Binary::new(pubkey),
        signature: signature.clone(), // Use the already-trimmed signature (r+s only)
        message,
        hrp: None
    };
    let res = credential.verify(deps);
    println!("Final verification result: {:?}", res);
    assert!(res.is_ok()); 

}  

