
use cosmwasm_std::Uint128;
use cw_auths::{session_action, session_query};
use saa_common::Empty;
use saa_schema::saa_type;


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



#[session_action]
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



#[session_query(ExecuteMsg)]
pub enum QueryMsg {

    #[returns(Vec<Coin>)]
    GetBalance {},

    #[returns(String)]
    REAllyLongAnnoyingQuery(String),


    #[returns(Option<Empty>)]
    StrumQuery {
        #[strum(to_string = "{{ \"get_balance\": {{ \"address\": \"{address}\" }} }}")]
        address: String,
    },
}
