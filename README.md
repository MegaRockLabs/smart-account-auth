![Crates.io Version](https://img.shields.io/crates/v/smart-account-auth?style=flat-square)
![NPM Version](https://img.shields.io/npm/v/smart-account-auth?style=flat-square&color=%233178C6)

# Smart Account Authentication

Authentication Library / SDK for working with various cryptographic credentials / authenticators
- Client-side tools for requesting credentials and their serializations 
- Verification (+ storage) logic for Rust environments. 
- Ideal for smart accounts, wallets and apps with built-in authentication 

## Goals and Focus-Area
- Definition of useful data structure, traits and utility functions
- Formatting data according to specs. Primarily with use of envelopes
- Serialisation and deserialisation of the data depending on context
- Passing data to underlying cryptographic APIs and libraries
- Dealing with batches / multiple credentials at the same time 


### Cryptography
- ⚡ Delegates verification to available APIs for efficiency 
- ⚙️ Native version relies on [cosmwasm-crypto](https://crates.io/crates/cosmwasm-crypto)

### Other Info

- **Encoding:** By default using `base64` everywhere. The exceptions are primarily when it makes sense according to the specs of a credential such as Eth addresses using `hex` or webauthn challenge using `base64url` 

## Supported Credentials
- Ethereum (EVM) personal sign
- Cosmos Arbitrary (036)
- Passkeys / Webauthn
- Secp256k1 / Secp256r1 / Ed25519 Curves

## Virtual Machine Support
- Cosmwasm  
- SecretWasm      
- Cosmwasm 1.5.x  - Temporary support
- Ink / Substrate -  Types only
- Solana (SVM)    -  Types only

# Smart Contracts / Programs

## Installation

```bash
# Add the library to your project
cargo add smart-account-auth
```

You can also give the library an alias to simplify typing
```toml
# To import for CosmWasm(v1) contracts with all default features 
saa  = { package = "smart-account-auth", version = "0.26.9", features = ["cosmwasm"] }
```

### Features

#### Feature Groups
- `default` - includes standard library, replay protection, and major credential types
- `majors` - includes the most commonly used credential types (Cosmos, Ethereum personal sign, Passkeys, Ed25519)
- `curves` - includes all supported cryptographic curves (Secp256r1, Secp256k1, Ed25519)
- `ethereum` - includes Ethereum personal sign and typed data support

#### Environment Features
Environment specific features that are mutually exclusive and shouldn't be used together. Pick depending on your virtual machine:
- `native` - for native rust code
- `cosmwasm` - for cosmwasm 2.x
- `cosmwasm_v1` - for cosmwasm 1.x 
- `secretwasm` - for cosmwasm of secret network
- `substrate` - for smart contracts written in ink (types only)
- `solana` - for solana programs (types only)

#### Credential Features
Credential specific features allow you to include / exclude specific credential types for better control and optimizing the binary size:

- `eth_personal` - for Ethereum personal sign message specification ( [EIP-191](https://eips.ethereum.org/EIPS/eip-191) )
- `eth_typed_data` - for Ethereum typed data (EIP-712) support
- `cosmos_arb` - for Cosmos Arbitrary message specification ( [ADR 036](https://github.com/cosmos/cosmos-sdk/blob/main/docs/architecture/adr-036-arbitrary-signature.md) )
- `cosmos_arb_addr` - for Cosmos address derivation from arbitrary signatures
- `passkeys` - for passkey based authentication ( [Webauthn](https://www.w3.org/TR/webauthn-3) )
- `ed25519` - for Ed25519 curve support
- `secp256k1` - for Secp256k1 curve support
- `secp256r1` - for Secp256r1 curve support

#### Additional Features
The following features give you access to additional logic related to better control or additional security:
- `session` - tool and primitives for session keys and message type identification 
- `replay` - enable replay protection and enforce signed messages to follow a specific format that includes nonces 
- `std` - whether to enable native Rust std library 

#### Extra Exports
The following features enable or disable inner primitives to either help you out or to reduce the binary size as much as possible:
- `utils` - inner utilities for serialization and preparing them for cryptography 
- `types` - enable minimalistic vm agnostic types ported from `cosmwasm_std` and `cw-utils`

#### Internal Features
The following features are not meant to be specified directly and used only for internal purposes 🚫
- `wasm` - common logic for different versions of cosmwasm or its derivatives

## Verification

### Single Credential
```rust
use cosmwasm_std::Binary;
use smart_account_auth::{traits::Verifiable, EvmCredential};

let evm_credential = EvmCredential {
    message:   Binary::from_base64( ** your message ** ),
    signature: Binary::from_base64( ** your signature **),
    signer:    String::from("0x...") // your eth address
}

# native rust code
evm_credential.verify()?;

# cosmwasm (feature) api code
evm_credential.verify_cosmwasm(deps.api)?;
```

### Multiple Credentials / Credential Data Wrapper

```rust
use smart_account_auth::{traits::{Verifiable, CredentialsWrapper}, CredentialData};

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
    // will be using passed hrp if available or the default
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

Requesting a credential is as simple as calling a function with a message to be signed and passing the necessary signer information
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

For passkeys you need to check whether a credential has been registered and prompt the user to register one if it hasn't

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

If replay attack protection is enabled on the contract side, the message to be signed must be a JSON string of the following format
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
- Authors of the library are also its main users. The experience is iteratively used to improve the SDK by understanding the needs and shifting more and more logic from apps to the lib. 
- `CosmWasm` retains the status of the primary target and used the most often during feature design stage and for tests. The main reason is being funded through quadratic funding on [DoraHacks](https://dorahacks.io/aez). 

## Disclaimer

- 🛠 In-Active development. Breaking changes might occur
- 👾 Test coverage to be improved and some bugs might occur
- ⚠️ The project hasn't been audited. Use at your own risk
