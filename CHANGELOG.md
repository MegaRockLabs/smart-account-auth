# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project **TRIES** to adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased]

## Added

- this document
- a separate testing crate
- new feature tag to optionally include inner `types`, `traits`, and `utils`
- minimalastic & vm agnostic versions of `Timestamp`, `Uint64` and `Uint128` from `cosmwasm_std`
- minimalastic & vm agnostic versions of `Expiration` and `Duration` from `cw-utils`
- `to_addr()` for the `Caller` credential

## Changed
- updated readme with features and focus-area
- moved `wasm` specific logic to sub-folders to reduce clutter
- hid some of the primtivies exposed globally before under the feature tags
- renamed module with static storage variables from `storage` to `stores` 
