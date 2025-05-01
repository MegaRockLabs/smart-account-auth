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
- Ethereum (EVM) personal sign
- Cosmos Arbitrary (036)
- Passkeys / Webauthn
- Secp256k1 / Secp256r1 / Ed25519 Curves

## Virtual Machine Support
- Cosmwasm [1.x]  -  Complete
- Cosmwasm [2.x]  -  Partial
- SecretWasm      -  Partial
- Ink / Substrate -  Partial
- Solana Seahorse -  Serialization



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

Environment specific features that are mutually exclusive and shouldn't be used together. Pick depending on your virtual machine
- `native` - for native rust code
- `substrate` - for smart contracts written in ink (substrate) 
- `solana` - for solana programs ( serialization only )
- `cosmwasm` - for cosmwasm 1.x
- `secretwasm` - for cosmwasm of secret network (testing)
- `injective` - for cosmwasm of injective network (in development)


Credential specifc features allow you to include / exclude specific credential types for better control and optimisizing the binary size

- `ethereum` - for Ethereum personal sign message specification (  [EIP-191](https://eips.ethereum.org/EIPS/eip-191) )
- `cosmos` - for Cosmos Arbitrary message specificion (  [ADR 036](https://github.com/cosmos/cosmos-sdk/blob/main/docs/architecture/adr-036-arbitrary-signature.md) )
- `passkeys` - for passkey based authentication ( [Webauthn](https://www.w3.org/TR/webauthn-3) )
- `curves` - verification of signature over any raw data using any of the supported curves (Ed25519, Secp256k1, Secp256r1) 
- `ed25519` - same as above but only for Ed25519 curve

The following features give you access to additional logic related to better control or additional security
- `storage` - expose methods and provide storage for storing and retrieving credentials from storage (coswasm only)
- `iterator`- expose methods for iterating and retrivieng all the credentials (coswasm only)
- `replay` - enable replay protection and enforce signed messages to follow a specific format that includes a nonce 
- `std` - whether to enable native Rust std library 

The following features enable or disable inner primitives to ether help you out or to reduce the binary size as much as possible
- `utils` - inner utilities for serialization and preparing them for cryptography 
- `types` - enable minimalistic vm agnostic types ported from `cosmwasm_std` and `cw-utils`
- `traits` - for importing trait `Verifiable` used internally or `CredentialsWrapper` to customise or simply use the wrapper methods 

The following credentials are not meant to be specified directly and used only internal purposes 🚫
- `wasm` - common logic for cosmwasm and it's derivatives like secretwasm, injective and others   

The following credentials are included by default
```ts
"ethereum", "cosmos", "ed25519", "passkeys", "replay", "iterator", "std", "traits"
```


## Verification

### Single Credential
```rust
use smart_acccount_auth::{Verifiable, EvmCredential, Binary};

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
use smart_acccount_auth::{Verifiable, CredentialsWrapper, CredentialData};

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


### Storage / Replay

The library is aim tp provide helpful primitives for verifying and then storing credentials in a secure and easy way
```rust
# first verify all the credentials and then store them stored in the storage
credential_data.save_cosmwasm(deps.api, deps.storage, &env, &info)?;
```

When replay attack protection is enabled, the library will enforce the message to include a contract address, a chain id and a nonce that should be equal to the current account number
 

After a successful verification an account contract must increment the nonce to prevent replay attacks
```rust
increment_account_number(deps.storage)?;
```

The library also provides a helper function to verify the signed actions which will verify the credentials and then increment the nonce automatically
```rust
verify_signed_actions(deps.api, deps.storage, &env, data)?;
```

#### Registries / Factories

In some cases you can want to use credemtials for accounts that are not yet created and therefire do not have an account number (unless instantiate2 is used). 

In cases like that you can use address of a registry / factory contract in data to sign. Later after the account contract is created you can create a new `Env` object with overwritten contract address

```rust
let registry_env = Env {
    contract: ContractInfo { address: info.sender.clone() },
    ..env.clone()
};

data.save_cosmwasm(api, storage, &registry_env, &info)?;
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


