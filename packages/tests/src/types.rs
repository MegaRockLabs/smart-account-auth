
use cosmwasm_std::Uint128;
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

