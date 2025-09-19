![Crates.io Version](https://img.shields.io/crates/v/smart-account-auth?style=flat-square)
![NPM Version](https://img.shields.io/npm/v/smart-account-auth?style=flat-square&color=%233178C6)

# Smart Account Authentication

Authentication Library / SDK  for working with various crypthograpghic credentials / authenticators

- Client-side tools for requesting credentials abd their serilizations
- Verification (+ storage) logic for Rust environments.
- Ideal for smart accounts, wallets and apps with build-in authentication

## Goals and Focus-Area

- Definition of useful data structure, trais and utlity functions
- Formatting data according to specs. Primarily with use of envelopes
- Serialisation and deserialisation of the date depending on context
- Passing data to underlying cryptographic APIs and libraries
- Dealing with batches / multuple credentials at the same time
- [FEAT] Protection against replay attacks
- [FEAT] Encapsulated storage of the credentials
- [FEAT] Encapsulated reconstruction & verification of credentials from payload

### Cryptography

- ⚡ Delegations verifcation to available APIs for efficency
- ⚙️ Native version relies on [cosmwasm-crypto](https://crates.io/crates/cosmwasm-crypto)

### Other Info

- **Encoding:** By default using `base64` everywhere. The exceptions are primarily when it makes sence according to the specs of a credential such as Eth addresses using `hex` or webauthn challenge using `base64url`

## Supported Credentials

| Credential               | Feature Flag     | Specification / Use Case                          |
|--------------------------|------------------|----------------------------------------------------|
| Ethereum Personal Sign   | ``ethereum``     | EVM-compatible signing (EIP-191)                  |
| Cosmos Arbitrary Sign    | ``cosmos``       | Human-readable msgs (ADR-036)                     |
| Passkeys (WebAuthn)      | ``passkeys``     | FIDO2 / WebAuthn public key authentication        |
| Secp256k1 / Secp256r1    | ``curves`` or ``ethereum`` | Raw signature verification on ECDSA curves |
| Ed25519                  | ``curves`` or ``ed25519`` | EdDSA signatures (e.g., Solana, Substrate)   |


## Virtual Machine Support

| Virtual Machine       | Version      | Support Level     | Notes                                  |
|-----------------------|-------------|-------------------|----------------------------------------|
| CosmWasm              | 1.x         | Complete          | Full signing and verification          |
| CosmWasm              | 2.x         | Partial           | Ongoing updates for v2 changes         |
| SecretWasm            | -           | Partial           | Based on CosmWasm; limited extensions  |
| Ink / Substrate       | -           | Partial           | Core types supported; more in development |
| Solana (Seahorse)     | -           | Serialization     | Only message serialization; no signing |

> Legend: Complete = fully supported, Partial = limited or experimental, Serialization = only data formatting available

# Smart Contracts / Programs

## Instalation

```bash
# Add the library to your project
cargo add smart-account-auth
```

You can also give the library an alias to simplify typing

```toml
# tp import for CosmWasm(v1) contracts with all default features 
saa  = { package = "smart-account-auth", version = "0.24.5", features = ["cosmwasm"] }
```

### Features

Environment specific features that are mutually exclusive and **shouldn't** be used together. Pick depending on your virtual machine:

| Feature         | Target Environment                     | Status        |
|----------------|----------------------------------------|---------------|
| ``native``     | Native Rust execution                  | Stable        |
| ``cosmwasm``   | CosmWasm 2.x smart contracts           | Stable        |
| ``cosmwasm_v1``| CosmWasm 1.x smart contracts           | Stable        |
| ``secretwasm`` | Secret Network (CosmWasm fork)         | In Development |
| ``substrate``  | Substrate ink! smart contracts         | In Development |
| ``solana``     | Solana programs (BPF)                  | In Development |

Credential specifc features allow you to include / exclude specific credential types for better control and optimisizing the binary size:

| Feature       | Purpose                                      | Specification |
|--------------|----------------------------------------------|---------------|
| ``ethereum`` | Ethereum personal sign messages              | [EIP-191](https://eips.ethereum.org/EIPS/eip-191) |
| ``cosmos``   | Cosmos arbitrary signing (human-readable)    | [ADR-036](https://github.com/cosmos/cosmos-sdk/blob/main/docs/architecture/adr-036-arbitrary-signature.md) |
| ``passkeys`` | WebAuthn / FIDO2 passkey authentication      | [WebAuthn](https://www.w3.org/TR/webauthn-3) |
| ``curves``   | Raw data sig verification (Ed25519, Secp256k1, Secp256r1) | Multi-curve support |
| ``ed25519``  | Sig verification only on Ed25519 curve       | Subset of ``curves`` |

The following features give you access to additional logic related to better control or additional security

| Feature     | Purpose                                      |
|------------|----------------------------------------------|
| ``session``| Tools & primitives for  session keys and message typing      |
| ``replay`` | Adds replay protection with nonce enforcement |
| ``std``    | Enables Rust `std` (vs `no_std` compatibility) |


The following features enable or disable inner primitives to ether help you out or to reduce the binary size as much as possible

| Feature      | Purpose                                         |
|-------------|-------------------------------------------------|
| ``utils``   | Serialization and crypto preprocessing tools   |
| ``types``   | Lightweight, VM-agnostic types (from `cosmwasm_std` / `cw-utils`) |
| ``traits``  | Exposes `Verifiable` *used internally* and `CredentialsWrapper` traits *to customise or simply use the wrapper methods* |

___

The following credentials are not meant to be specified directly and used only internal purposes 🚫

| Feature   | Purpose                              |
|----------|---------------------------------------|
| ``wasm`` | Shared logic for CosmWasm derivatives |


## Verification

### Single Credential

```rust
use cosmwasm_std::Binary;
use smart_acccount_auth::{traits::Verifiable, EvmCredential};

let evm_credential = EvmCredential {
    message:   Binary::from_base64( ** your message ** ),
    signature: Binary::from_base64( ** your signature **),
    signer:    String::from("0x...") // your eth address
}

# native rust code
evm_credential.verify()?:

# cosmwasm (feature) api code
evm_credential.verify_cosmwasm(deps.api)?;
```

### Multiple Credentials / Credentil Data Wrapper

```rust
use smart_acccount_auth::{traits::{Verifiable, CredentialsWrapper}, CredentialData};

let credential_data = CredentialData {
    credentials         :  vec![ ** your credentials here **  ],
    // whether to allow the sender address to be an authority over account
    // set to false if calling using a relayer 
    with_caller         :  Some(true),
    // index of "main" credential if it exists
    primary_index   :  Some(0)
}

# native rust code
credential_data.verify()?;

# cosmwasm (feature) api code
credential_data.verify_cosmwasm(deps.api)?;

// pick a credential under primary index, (first credential if not set)
let cred = data.primary();

// Examples of using the credential
let id = cred.id();

if cred.is_cosmos_derivable() {
    // wull be using passed hrp if available or the default
    let cosmos_address = cred.cosmos_address(deps.api);
}

```

# Typescript

## Installation

Add the library to your project

```bash
npm install smart-account-auth
```

## Usage

### Basics

Requsting a credemtial is as simple as calling a function with a message to be signed and passing the neccecary signer information

```typescript
import { getEthPersonalSignCredential } from 'smart-account-auth';
const ethCredential = await getEthPersonalSignCredential(window.ethereum, message)
```

or

```typescript
import { getCosmosArbitraryCredential } from 'smart-account-auth';
const cosmosCredential = await getCosmosArbitraryCredential(window.keplr, chainId, message)
```

### Passkeys

For passkeys you need to check whether a credential has been registeted and prompt the user to register one if it hasn't

```typescript
import { getPasskeyCredential, registerPasskey } from 'smart-account-auth'

// By default the library uses local storage to store passkeys
const stored = localStorage.getItem('passkeys');
let getPasskeyCredPromise : Promise<Credential>;

if (stored) {
    // id and pubkey will be read from local storage
    getPasskeyCredPromise = getPasskeyCredential(message)
} else {
    const passkeyName = "My App Passkey";
    const { id, pubkey } = await registerPasskey(passkeyName);
    getPasskeyCredPromise =  getPasskeyCredential(message, id, pubkey)
}

const credential = await getPasskeyCredPromise;
```

### Replay Attack Protection

If replay attack protection is enabled on the contract side, the message to be signed must be a json strong of the following format

```typescript
type DataToSign = {
    chain_id: string,
    contract_address: string,
    messages: any[],
    nonce: string
  }
```

The order of the fields is important (set to alphabetical order) and the nonce must be equal to the current account number

### Multiple Credentials / Credential Data Wrapper

You can use `CredentialData` object to wrap multiple credentials and efficiently verify them in a single call

```typescript
import { CredentialData } from 'smart-account-auth'

const data : CredentialData = {
    // whether to allow the sender address to be an authority over account
    with_caller: false,
    // credentials that can control the account
    credentials: [ethCredential, passkeyCredential],
    // index of "main" credential that will be used by default
    primaryIndex: 0
} 
```

### Meta / Usage

- OpenSource -> Low Funding / Resources -> Contributions are especially needed and welcomed
- Authors of the library are also its main users. The expirience is iteratively used to improve the SDK by understaning the needs and shifting more and more logic from apps to the lib.
- `CosmWasm` retains the status of the primary target and used the most often during feature design stage and for tests. The main reason is being funded through quadrating funding on [DoraHacks](https://dorahacks.io/aez).

## Disclaimer

- 🛠 In-Active development. Breaking changes might occur
- 👾 Test coverage to be improved and some bugs might occur
- ⚠️ The project hasn't been audited. Use at your own risk
