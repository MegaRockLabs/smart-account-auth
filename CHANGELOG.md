# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
Project **TRIES** adhering to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), however going through the active development stage and can't guarantee it (FOR NOW).

<!-- next-header -->

## [Unreleased] Rust

## Added

- this document
- a separate testing package for (lib) integration tests
- session actions to be used by session keys and `session` feature tag
- new feature tag to optionally include inner `types`, `traits`, and `utils`
- minimalastic & vm agnostic versions of `Timestamp`, `Uint64` and `Uint128` from `cosmwasm_std`
- minimalastic & vm agnostic versions of `Expiration` and `Duration` from `cw-utils`
- `From<&str>` to `Caller` credential


## Changed
- type of CredentialId has changed from `Vec<u8>` to `String`
- response types that had ids were also changed from  `Binary` to `String` 
- storage method renamed to exclude `_cosmwasm` suffix
- stopped converting `PasskeyCredential::credential_data.challenge` from `base64` to `base64` on client side.
- hid some of the primtivies that were previously exposed globally under the feature tags
- renamed module with static storage variables from `storage` to `stores` 
- moved `wasm` specific logic to sub-folders to reduce clutter
- updated readme with features and focus-areas


## Fixed
- validation for max and min number of credentials in `CredentialData`
- redundant (re-)validations 



## [Unreleased] Typescript


## Changed
- stopped converting `PasskeyCredential::credential_data.challenge` from `base64` to `base64` 