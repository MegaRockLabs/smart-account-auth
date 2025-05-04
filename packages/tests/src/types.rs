
use saa_schema::{session_action, wasm_serde};
use smart_account_auth::{types::uints::Uint128, CredentialData};


#[wasm_serde]
pub struct Coin {
    pub denom: String,
    pub amount: Uint128,
}


#[wasm_serde]

pub enum BankMsg {
    Send {
        to_address: String,
        amount: Vec<Coin>,
    },
    Burn { amount: Vec<Coin> },
}



#[wasm_serde]
pub enum CosmosMsg {
    Bank(BankMsg),
    Staking {},
}
    


#[session_action]
#[wasm_serde]
pub enum ExecuteMsg {

    Execute { 
        msgs: Vec<CosmosMsg> 
    },

    #[strum(to_string = "{{ \"mint_token\": {{ \"minter\": \"{minter}\" }} }}")]
    MintToken {
        minter: String,
        msg: Option<CosmosMsg>
    },

    #[strum(to_string = "{{\"transfer_token\":{{\"id\":\"{id}\",\"to\":\"{to}\"}}}}")]
    TransferToken {
        id: String,
        to: String,
    },

    UpdateAccountData {
        account_data: Option<CredentialData>,
    },

    #[strum(to_string = "freeeeeze")]
    Freeze {},

    Purge {},
}



