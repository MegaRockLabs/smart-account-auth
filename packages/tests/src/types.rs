
use cosmwasm_std::Uint128;
use saa_schema::{session_action, session_query, wasm_serde};


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
pub enum StakingMsg {
    Delegate { validator: String, amount: Coin },
}


#[wasm_serde]
pub enum CosmosMsg {
    Bank(BankMsg),
    Staking(StakingMsg),
    Simple {}
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


    #[strum(to_string = "freeeeeze")]
    Freeze {},

    Purge {},
}



#[session_query]
#[wasm_serde]
pub enum QueryMsg {

    GetBalance {},
   
}
