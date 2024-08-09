# Smart Account Authentication

Rust crates for smart contract authentication supporting most of the existing authentication mechanisms

# Usage 

### Single Credential
```rust
use smart_acccount_auth::{Verifiable, EvmCredential};

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
