use saa_schema::wasm_serde;
use schemars::JsonSchema;
use strum::{IntoDiscriminant, VariantNames, VariantArray};

use crate::{msgs::DerivationMethod, traits::DerivableMsg};

use strum_macros::{Display, EnumString, EnumDiscriminants};




#[wasm_serde]
#[derive(EnumDiscriminants)]
#[strum_discriminants(name(SessionQueryName),
    derive(Display, EnumString),
    strum(serialize_all = "snake_case")
)]
pub enum SessionQueryMsg<M> 
    where 
         M: QueryUsesActions,
            M::ActionMsg : IntoDiscriminant<Discriminant: VariantArray + 'static>,
{
    
    AllQueries {},

    AllActions {},

    Derive {
        message: M::ActionMsg,
        method: Option<DerivationMethod>,
    }
}


pub trait QueryUsesActions
where
    Self : DerivableMsg + VariantNames + IntoDiscriminant<Discriminant: VariantArray + 'static>,
    Self::ActionMsg :  DerivableMsg + JsonSchema +
         VariantNames + IntoDiscriminant<Discriminant: VariantArray + 'static>,
{
    type ActionMsg;
}


pub trait SessionQueriesMatch : QueryUsesActions
where
    <<Self as QueryUsesActions>::ActionMsg as IntoDiscriminant>::Discriminant: 'static,
{
    fn match_queries(&self) -> Option<SessionQueryMsg<Self>>;
}
