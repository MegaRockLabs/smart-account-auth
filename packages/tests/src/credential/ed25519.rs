use saa_common::{Binary, Verifiable};
use smart_account_auth::Ed25519;
use crate::utils::get_mock_deps;

#[test]
fn can_check_ed25519() {
    let deps = get_mock_deps();
    let deps = deps.as_ref();
    let signature = Binary::from_base64("6uWPnnvtgyLMwQyh8bQee5uJCWliwqSIwBHVH0W7IbrfhuD9xfYTkILIk2HnnHAeCQpeciOFyuvlHqG3Uhk1Bg==").unwrap();
     let credential = Ed25519 { 
        signature, 
        pubkey: Binary::from_base64("hSbJHnhPYaTVg2AitE4ixJWi4zrEzRiOtsOTFP4LB5w=").unwrap(), 
        message: Binary::new("{\"chain_id\":\"constantine-3\",\"contract_address\":\"archway16qy02mwau05fn289h6mqm6qv4haqa6s2quwnjch0zch6a2yjr97qqv5ulg\",\"messages\":[\"Create TBA account\"],\"nonce\":\"0\"}".as_bytes().to_vec())
    };
    let res = credential.verify(deps);
    assert!(res.is_ok()); 
}

