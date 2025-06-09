
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