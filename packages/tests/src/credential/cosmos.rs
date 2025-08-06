use saa_common::{Binary, Verifiable};
use smart_account_auth::CosmosArbitrary
;

use crate::utils::get_mock_deps;




#[test]
fn can_check_cosmos_arbitrary() {

    let deps = get_mock_deps();
    let deps = deps.as_ref();
    let pubkey = Binary::from_base64("Ar2rP/aLIcAK7lLsBlpWAM9CT8bhJHE/SxMFj5N9n1Ux").unwrap();
    let signature = Binary::from_base64("oWGyouMl0su267brUjt47pesmOxxshkxA63Ubpt/LP0z4M5icT/zlGqai3gRkbJ+tr9812DGhXH5aS9VLSmgKw==").unwrap();
    

    let credential = CosmosArbitrary { 
        pubkey, 
        signature, 
        address: "stars16z43tjws3vw06ej9v7nrszu0ldsmn0eyjnjpu8".to_string(),
        message: Binary::from_base64("eyJjaGFpbl9pZCI6InRlc3RpbmciLCJjb250cmFjdF9hZGRyZXNzIjoic3RhcnMxbmM1dGF0YWZ2NmV5cTdsbGtyMmd2NTBmZjllMjJtbmY3MHFnamx2NzM3a3RtdDRlc3dycTA5NmNqYSIsIm1lc3NhZ2VzIjpbIkNyZWF0ZSBUQkEgYWNjb3VudCJdLCJub25jZSI6IjAifQ==").unwrap()
    };

    let res = credential.verify(deps);
    println!("Res: {:?}", res);
    //println!("Res: {:?}", res);
    assert!(res.is_ok());

}

