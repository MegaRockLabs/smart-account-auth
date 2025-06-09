
#[cfg(feature = "cosmwasm")]
use saa_common::wasm::{Addr, Deps, Api};
use saa_common::{
    ensure, AuthError, Binary, CredentialError, CredentialId, CredentialInfo, CredentialName, 
    String, ToString, Verifiable, Identifiable
};

use CredentialName::CosmosArbitrary as CosmosName;


#[saa_schema::saa_type]
pub struct CosmosArbitrary {
    pub pubkey:    Binary,
    pub signature: Binary,
    pub message:   Binary,
    #[cfg(not(feature = "cosmos_arb_cache"))]
    pub hrp:       Option<String>,
    #[cfg(feature = "cosmos_arb_cache")]
    pub address:   String
}


#[cfg(any(feature = "cosmwasm", feature = "native"))]
impl CosmosArbitrary {

    #[allow(unused_variables)]
    #[cfg(feature = "cosmwasm")]
    fn get_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        #[cfg(feature = "cosmos_arb_cache")]
        return Ok(api.addr_validate(&self.address)?);
        #[cfg(not(feature = "cosmos_arb_cache"))]
        if let Some(ref hrp) = self.hrp {
            Ok(Addr::unchecked(saa_crypto::pubkey_to_address(&self.pubkey, hrp)?))
        } else {
            Err(AuthError::Generic("Must provide prefix for the public key".to_string()))
        }
    }

    #[cfg(not(feature = "cosmwasm"))]
    fn get_address(&self) -> Result<String, AuthError> {
        #[cfg(feature = "cosmos_arb_cache")]
        return self.address.clone();
        #[cfg(not(feature = "cosmos_arb_cache"))]
        if let Some(ref hrp) = self.hrp {
            saa_crypto::pubkey_to_address(&self.pubkey, hrp)?;
        } else {
            Err(AuthError::Generic("Must provide prefix for the public key".to_string()))
        }
    }

    fn message_digest(&self, addr: &str) -> [u8; 32] {
        saa_crypto::sha256(super::utils::wrap_msg_arb_036(
                addr, 
                &self.message.to_string()
            ).as_bytes()
        )
    }
}


impl Identifiable for CosmosArbitrary {
    fn id(&self) -> CredentialId {
        self.pubkey.to_string()
    }
    
    fn name(&self) -> CredentialName {
        CosmosName
    }
}


impl Verifiable for CosmosArbitrary {
    
    fn message(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Borrowed(self.message.as_slice())
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.signature.len() > 0 &&
            self.message.to_string().len() > 0 && 
            self.pubkey.len() > 0,  CredentialError::MissingData(CosmosName)
        );
        Ok(())
    }
    
    #[cfg(any(feature = "native", feature = "cosmwasm"))]
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: Deps
    ) -> Result<CredentialInfo, AuthError> {
        use saa_common::CredentialAddress;

        let address = self.get_address(
            #[cfg(feature = "cosmwasm")]
            deps.api
        )?;
        #[cfg(all(feature = "native", not(feature = "cosmwasm")))]
        let res = saa_crypto::secp256k1_verify(
            &self.message_digest(address.as_str()),
            &self.signature, 
            &self.pubkey
        )?;
        #[cfg(feature = "cosmwasm")]
        let res = deps.api.secp256k1_verify(
            &self.message_digest(address.as_str()),
            &self.signature, 
            &self.pubkey
        )?;
        saa_common::ensure!(res, AuthError::Signature(CosmosName, self.id()));
        let hrp = address.as_str().split('1').next().map(|s| s.to_string());
        Ok(CredentialInfo {
            hrp,
            extension: None,
            name: CosmosName,
            address: Some(CredentialAddress::Bech32(address)),
        })
    }

}