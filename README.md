# Smart Account Authentication

Rust crates for smart contract authentication supporting most of the existing authentication mechanisms


# Supported Credentials
- Ethereum (EVM) personal sign
- Cosmos Arbitrary (036)
- Passkeys / Webauthn
- Secp256k1 / Secp256r1 / Ed25519 Curves

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
    message:   Binary::from_base64( ** your message ** ),
    signature: Binary::from_base64( ** your signature **),
    signer:    String::from("0x...") // your eth address
}

# native rust code
evm_credential.verify()?:

# cosmwasm (feature) api code
# third argument is for deriving a prefix which is not needed for ethereum
evm_credential.verified_cosmwasm(deps.api, &env, &None)?;
```

### Multiple Credentials

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

let verified = credential_data.verified_cosmwasm(deps.api, &env, &Some(info)?;

let primary_credential = verified.primary();

```
