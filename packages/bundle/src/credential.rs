use saa_common::{Verifiable, AuthError, CredentialId};
use saa_custom::caller::Caller;
use saa_schema::wasm_serde;

#[cfg(feature = "curves")]
use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};

#[cfg(feature = "passkeys")]
use saa_custom::passkey::PasskeyCredential;

#[cfg(feature = "ethereum")]
use saa_custom::eth::EthPersonalSign;

#[cfg(feature = "cosmos")]
use saa_custom::cosmos::arbitrary::CosmosArbitrary;

#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm;


#[wasm_serde]
pub enum Credential {
    Caller(Caller),

    #[cfg(feature = "ethereum")]
    EthPersonalSign(EthPersonalSign),

    #[cfg(feature = "cosmos")]
    CosmosArbitrary(CosmosArbitrary),

    #[cfg(feature = "passkeys")]
    Passkey(PasskeyCredential),

    #[cfg(feature = "curves")]
    Secp256k1(Secp256k1),

    #[cfg(feature = "curves")]
    Secp256r1(Secp256r1),
    
    #[cfg(feature = "curves")]
    Ed25519(Ed25519),
}


impl Credential {
    pub fn name(&self) -> &'static str {
        match self {
            Credential::Caller(_) => "caller",

            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(_) => "eth_personal_sign",

            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(_) => "cosmos-arbitrary",

            #[cfg(feature = "passkeys")]
            Credential::Passkey(_) => "passkey",

            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(_) => "secp256k1",
                    Credential::Secp256r1(_) => "secp256r1",
                    Credential::Ed25519(_) => "ed25519",
                    _ => unreachable!(),
                }
            } 
        }
    }

    pub fn value(&self) -> &dyn Verifiable {
        match self {
            Credential::Caller(c) => c,

            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c,

            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c,

            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c,

            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c,
                    Credential::Secp256r1(c) => c,
                    Credential::Ed25519(c) => c,
                    _ => unreachable!(),
                }
            }
        }
    }
    
}

impl Verifiable for Credential {

    fn id(&self) -> CredentialId {
        self.value().id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.value().validate()
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.value().verify()
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(
        &self, api:  
        &dyn cosmwasm::Api, 
        env: &cosmwasm::Env, 
        info: &Option<cosmwasm::MessageInfo>
    ) -> Result<Self, AuthError> 
        where Self: Clone
    {
        self.validate()?;
        Ok(match self {
            Credential::Caller(c) => Credential::Caller(c.verified_cosmwasm(api, env, info)?),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => Credential::EthPersonalSign(c.verified_cosmwasm(api, env, info)?),

            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => Credential::CosmosArbitrary(c.verified_cosmwasm(api, env, info)?),

            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => Credential::Passkey(c.verified_cosmwasm(api, env, info)?),

            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) 
                        => Credential::Secp256k1(c.verified_cosmwasm(api, env, info)?),

                    Credential::Secp256r1(c) 
                        => Credential::Secp256r1(c.verified_cosmwasm(api, env, info)?),

                    Credential::Ed25519(c) 
                        => Credential::Ed25519(c.verified_cosmwasm(api, env, info)?),

                    _ => unreachable!(),
                }
            }
        })
    }

}

pub type Credentials = saa_common::Vec<Credential>;