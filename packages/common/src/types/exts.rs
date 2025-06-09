use saa_schema::saa_type;
use crate::cfg_mod_use;

cfg_mod_use!("passkeys", passkey);
cfg_mod_use!("eth_typed_data", eth_typed);


#[saa_type(no_deny)]
#[non_exhaustive]
pub enum InfoExtension {

    #[cfg(feature = "passkeys")]
    Passkey(passkey::PasskeyInfo),

    #[cfg(feature = "eth_typed_data")]
    EthTypedData(eth_typed::EthTypedInfo),

    Custom(crate::Binary),
}



#[saa_type(no_deny)]
#[non_exhaustive]
pub enum PayloadExtension {

    #[cfg(feature = "passkeys")]
    Passkey(passkey::PasskeyPayload),

    #[cfg(feature = "eth_typed_data")]
    EthTypedData(eth_typed::EthTypedPayload),

    Custom(crate::Binary),
}

