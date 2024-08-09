# Smart Account Authentication

Rust crates for smart contract authentication supporting most of the existing authentication mechanisms


# Supported Credentials
- Ethereum (EVM) personal sign
- Cosmos Arbitrary (036)
- Passkeys / Webauthn
- Secp256k1 / Secp256r1 / Ed25519 Curves
- (WIP) JWT / Oauth / Social Sign

# Virtual Machine Support
- Cosmwasm [1.x]  -  Complete
- Cosmwasm [2.x]  -  Partial
- Ink / Substrate -  Partial
- Solana Seahorse -  Partial


# Usage 

### Single Credential
```rust
use smart_acccount_auth::{Verifiable, EvmCredential, Binary};

let evm_credential = EvmCredential {
    pub message:   Binary,
    pub signature: Binary,
    pub signer:    String,
}

# native rust code
evm_credential.verify()?:

# cosmwasm (feature) api code
evm_credential.verified_cosmwasm(deps.api, &env, &None)?;
```

### Multiple Credentials

```rust
use smart_acccount_auth::{Verifiable, CredentialsWrapper, CredentialData};

let credential_data = CredentialData {
    credentials         :  vec![ ** your credentials here **  ],
    // whether to allow current sender address to be an authority 
    with_caller         :  Some(true),
    // index of "main" credential if one exist 
    pub primary_index   :  Some(0)
}

let verified = credential_data..verified_cosmwasm(deps.api, &env, &Some(info)?;

let primary_credential = verified.primary();

...

```
