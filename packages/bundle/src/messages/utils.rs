

#[cfg(feature = "session")]
use {saa_common::FromStr, strum::IntoEnumIterator};

#[cfg(feature = "replay")]
use {
    crate::msgs::{MsgDataToSign, MsgDataToVerify},
    saa_common::{wasm::Env, from_json, AuthError},
};


#[cfg(all(not(feature = "replay"), feature = "session"))]
pub fn convert<M: serde::de::DeserializeOwned>(
    data: impl AsRef<[u8]>,
    name: &str,
) -> Result<M, saa_common::AuthError> {

    saa_common::from_json(data)
    .map_err(|_| saa_common::AuthError::Convertation(name.to_string()))
}



#[cfg(feature = "replay")]
pub fn convert<M : serde::de::DeserializeOwned>(
    data: impl AsRef<[u8]>
) -> Result<crate::msgs::MsgDataToSign<M>, saa_common::AuthError> {
    saa_common::from_json(data)
    .map_err(|_| saa_common::AuthError::Convertation("MsgDataToSign".to_string()))
}



#[cfg(feature = "replay")]
pub fn convert_validate(
    data: impl AsRef<[u8]>,
    env: &Env,
    nonce: u64
) -> Result<(), AuthError> {
    let msg : MsgDataToVerify = from_json(data)
                            .map_err(|_| AuthError::Convertation("MsgDataToVerify".to_string()))?;
    msg.validate(env, nonce)?;
    Ok(())
}



#[cfg(feature = "replay")]
pub fn convert_validate_return<M : serde::de::DeserializeOwned>(
    data: impl AsRef<[u8]>,
    env: &Env,
    nonce: u64
) -> Result<MsgDataToSign<M>, AuthError> {
    let msg  = convert(data)?;
    msg.validate(env, nonce)?;
    Ok(msg)

}


#[cfg(feature = "session")]
pub(crate) fn is_session_action_name(name: &str) -> bool {
    crate::msgs::SessionActionName::iter()
        .any(|action| {
            if action.as_ref() == name {
                return true;
            }
            if let Ok(act) = crate::msgs::SessionActionName::from_str(name) {
                return action == act;
            }
            false
        })
}



