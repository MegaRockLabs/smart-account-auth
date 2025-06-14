
use cosmwasm_std::Uint128;
use saa_schema::{saa_derivable, saa_type};


#[saa_type]
pub struct Coin {
    pub denom: String,
    pub amount: Uint128,
}


#[saa_type]

pub enum BankMsg {
    Send {
        to_address: String,
        amount: Vec<Coin>,
    },
    Burn { amount: Vec<Coin> },
}

#[saa_type]
pub enum StakingMsg {
    Delegate { validator: String, amount: Coin },
}


#[saa_type]
pub enum CosmosMsg {
    Bank(BankMsg),
    Staking(StakingMsg),
    Simple {}
}



#[saa_derivable]
pub enum ExecuteMsg {
    #[strum(to_string = "{{ \"execute\": {{ \"msgs\": {msgs:?} }} }}")]
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
