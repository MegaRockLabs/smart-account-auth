# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),

Project **tries** adhering to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), however due to going through the active development stage there might be small deviations.
The promise only applies to the main crate `smart-account-auth` (in packages/bundle) and not to other sub-packages.

<!-- next-header -->

## [Unreleased]

## Added
- Feature tags for including every single one of the supported credentials separately
- `ClientData` of passkeys can now contain additional fields on top od the most common `other_keys_can...`
- Testing folder that depends on external crate `cw-auths` 

## Changed
- `cosmwasm_1` renamed to `cosmwasm_v1`  
- `ethereum` feature is changed to include all ethereum related credentials. The previous behaviour can enabled with `eth_personal` separately
- `PasskeyPayload` now requires the value of `other_keys_can...` to be passed. Previously it was using `Option<bool>` and then proceeding with the default value of the long "do not compare clientDataJSON aga.."
- Exporting the whole `cosmwasm_std` package when  both `types` are any wasmic VM features are enabled (Vs few selected primtives)

## Fixed
- Overall optimisations, refactoring and including less dependencies when possible
- `PasskeyCredential` and `Secp256r1` are now in a separate crate and don't include `p256` crate for CosmWasm 2.0
- `to_json_string` imports and definitions

## Removed
- `injective` feature until adding complete support


## [Unreleased] Typescript

## Changed
- stopped converting `PasskeyCredential::credential_data.challenge` from `base64` to `base64-url` 


## [0.25.0] - 2024-12-18 

## Added

- new types, trairs and other primitives for session keys and derivable actions. Available under new `session` feature tag
- a separate testing package for lib tests
- new feature tags that allow to optionally include additional inner `types`, `traits`, and `utils`
- minimalastic and vm agnostic versions of `Timestamp`, `Uint64` and `Uint128` from `cosmwasm_std`
- minimalastic and vm agnostic versions of `Expiration` and `Duration` from `cw-utils`
- added macros `saa-error` and `saa_derivable` for internal use
- this document

## Changed
- type of CredentialId has changed from `Vec<u8>` to `String`
- response types that had ids were also changed from  `Binary` to `String` 
- `Caller` credential is now an enum struct (after being a regular struct)
- Minor changes to `ClientData` of `PasskeyCredential` related to optional key fields
- renamed module with static storage variables from `storage` to `stores` 
- renamed `saa_type` to `saa_type` and added ability to omit exlusion of unknown properties by passing `no_deny`
- split type macros into separate files for each type
- `CredentialData`'s method was renamed to `with_native` and now inject the new caller from attached info only if the flag is set to `Some(true)` and return a miiror copy otherwise
- renamed `construct_credential` to `build_credential` and expose by default
- updated readme with features and focus-areas

## Removed
- All storage related types and primitives and logic have been removed to be moved to a separate package for each VM  
- Deleted  `storage` and `iterator` feature tags

## Fixed
- validation for max and min number of credentials in `CredentialData`
- fixed situatino with redundant (re-)validations 
- removed clutter from complex derrive clauses
- macros 


