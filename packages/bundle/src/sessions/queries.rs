use saa_schema::wasm_serde;

use crate::{msgs::DerivationMethod, traits::DerivableMsg};

use strum_macros::{Display, EnumString, EnumDiscriminants};




#[wasm_serde]
#[derive(EnumDiscriminants)]
#[strum_discriminants(name(SessionQueryName),
    derive(Display, EnumString),
    strum(serialize_all = "snake_case")
)]
pub enum SessionQueryMsg<M : DerivableMsg> {
    AllQueries {},
    Derive {
        message: M,
        method: Option<DerivationMethod>,
    }
}





pub trait SessionQueriesMatch : DerivableMsg  {
    fn match_queries(&self) -> Option<SessionQueryMsg<Self>>;
}

