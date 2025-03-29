import type { Credential as AuthCredential, ClientData, PasskeyCredential } from "./types";
import { toUtf8 } from "secretjs";
import { decode } from "cbor-x";
import { v4 } from "uuid";

import { COSEKey } from "./types";
import { fromUtf8, toBase64 } from "@cosmjs/encoding";
import { random_32 } from "@solar-republic/neutrino";



export const base64ToUrl = (base64: string)  => {
  let base64Url = base64.replace(/\+/g, '-').replace(/\//g, '_');

  // Remove padding if present
  base64Url = base64Url.replace(/=+$/, '');

  return base64Url;
}


export const urlToBase64 = (base64Url: string) => {
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
      base64 += '='.repeat(4 - padding);
  }
  return base64;
}




export const registerPasskey = async (
    name                  :   string,
    challenge?            :   string | Uint8Array,
    rp?                   :   PublicKeyCredentialRpEntity,
    displayName?          :   string,
    options?              :   PublicKeyCredentialCreationOptions,
    saveToLocalStorage    :   boolean | string = true,
    signal?               :   AbortSignal,
) : Promise<{ id: string, pubkey: string }> => {

    if (challenge) {
        challenge = typeof challenge === "string" ? toUtf8(challenge) : challenge
    } else {
        challenge = random_32();
    }

    rp ??= { name: window.location.hostname };
    displayName ??= name;

    const id = new Uint8Array(Buffer.from(v4()));

    const createOptions : CredentialCreationOptions = {
      publicKey: {
        rp,
        user: { id, name, displayName },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        challenge,
        timeout: 60000,
        excludeCredentials: [],
        authenticatorSelection: {
          requireResidentKey: false,
          userVerification: "preferred",
        },
        ...options,
      },
      signal
    };

    const credential = await navigator.credentials.create(createOptions);
    const createCredential = assertPublicKeyCredential(credential);
    const attestationResponse = assertAttestationResponse(
        createCredential.response
    );

    const decoded = decodeAttestationObject(
        new Uint8Array(attestationResponse.attestationObject)
    );

    const registered = { 
        id: toBase64(decoded.authData.attestedCredentialData.credentialId),
        pubkey: getBase64PublicKey(decoded.authData.attestedCredentialData.credentialPublicKey)
    };

    if (saveToLocalStorage) {
        const storageKey = saveToLocalStorage === true ? "passkeys" : saveToLocalStorage;
        const passkeys = localStorage.getItem(storageKey) || "{}";
        const parsed = JSON.parse(passkeys) as Record<string, string>;
        parsed[registered.id] = registered.pubkey;
        localStorage.setItem(storageKey, JSON.stringify(parsed));
    }   

    return registered;
}



export const getPasskeyCredential = async (
    challenge        :  string | Uint8Array,
    id?              :  string,
    pubkey?          :  string,
    options?         :  PublicKeyCredentialRequestOptions,
    loadFromStorage  :  boolean | string = true,
    name?            :  string,
) : Promise<AuthCredential & { passkey: PasskeyCredential }>  => {

    challenge = typeof challenge === "string" ? toUtf8(challenge) : challenge

    if (!id) {
        if (loadFromStorage) {
            const storageKey = loadFromStorage === true ? "passkeys" : loadFromStorage;
            const passkeys = localStorage.getItem(storageKey) || "{}";
            const parsed = JSON.parse(passkeys) as Record<string, string>;
            const keys = Object.keys(parsed);
            if (keys.length === 0) throw new Error(`No Passkeys Found`);
            id = keys[0];
            pubkey = parsed[id];
        } else if (name) {
          const res = await registerPasskey(name);
          id = res.id;
          pubkey = res.pubkey;
        } else {
            throw new Error(`No Passkey Provided`);
        }
    }

    const allowCredentials : PublicKeyCredentialDescriptor[] = id 
        ? [{ id: Buffer.from(id, "base64"), type: "public-key" }] 
        : [];
        
        
    const credentialRequestOptions: CredentialRequestOptions = {
        publicKey: {
            allowCredentials,
            challenge,
            timeout: 60000,
            ...options
        },
    };

    const credential = await navigator.credentials.get(credentialRequestOptions);
    const getCredential = assertPublicKeyCredential(credential);
    const response = assertAssertionResponse(getCredential.response);
    const client_data : ClientData = JSON.parse(fromUtf8(new Uint8Array(response.clientDataJSON))) as ClientData

    client_data.challenge = urlToBase64(client_data.challenge);

    const passkey : PasskeyCredential = {
      id,
      pubkey,
      signature: toBase64Sig(new Uint8Array(response.signature)),
      authenticator_data: toBase64(new Uint8Array(response.authenticatorData)),
      client_data,
    }

    return { passkey }
}



const toBase64Sig = (data : Uint8Array): string => {
  let l = data.length;

  if (l < 2 || data[0] != 0x30) throw new Error('Invalid signature tag');
  if (data[1] !== l - 2) throw new Error('Invalid signature: incorrect length');

  const { d: r, l: sBytes } = parseInt(data.subarray(2));
  const { d: s, l: rBytesLeft } = parseInt(sBytes);

  if (r.length !== 32 || s.length !== 32) { 
    throw new Error('Invalid signature: invalid length of r or s values'); 
  }
  if (rBytesLeft.length) {
    throw new Error('Invalid signature: left bytes after parsing');
  }
  const sig = new Uint8Array(64);
  sig.set(r, 32 - r.length);
  sig.set(s, 64 - s.length);

  return toBase64(sig);
}




const parseInt = (data: Uint8Array): { d: Uint8Array; l: Uint8Array } => {
  if (data.length < 2 || data[0] !== 0x02) throw new Error('Invalid signature integer tag');
  const len = data[1];
  const res = data.subarray(2, len + 2);
  if (!len || res.length !== len) {
    throw new Error('Invalid signature integer: wrong length');
  }
  if (res[0] === 0x00 && res[1] <= 0x7f) {
    throw new Error('Invalid signature integer: trailing length');
  }
  const d = res.length == 33 && res[0] == 0x00 ? res.subarray(1) : res; 
  return { d, l: data.subarray(len + 2) }; // d is data, l is left
}


const decodeCredentialPublicKey = (res: Uint8Array): COSEKey => {
    const decoded = decode(res);
    return {
      crv: decoded[-1],
      x: decoded[-2],
      y: decoded[-3],
      privateKey: decoded[-4],
      kty: decoded[1],
      kid: decoded[2],
      alg: decoded[3],
      key_ops: decoded[4],
      "Base IV": decoded[5],
    };
};


const getBase64PublicKey = (coseKey: COSEKey): string => {
    const {x, y} = coseKey;
    const concat = new Uint8Array(x.length + y.length + 1);
    concat.set([0x04], 0);
    concat.set(x, 1);
    concat.set(y, x.length + 1);
    return toBase64(concat);
}
  

export const decodeAttestationObject = (
    bytes: Uint8Array
  ): {
    authData: {
      // 32 bytes
      rpIdHash: Uint8Array;
      // 1 byte
      flags: Uint8Array;
      // 4 bytes
      signCount: Uint8Array;
      // var - https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data#attestedcredentialdata
      attestedCredentialData: {
        // 16 bytes
        AAGUID: Uint8Array;
        // 2 bytes
        credentialIdLength: Uint8Array;
        // credentialIdLength bytes
        credentialId: Uint8Array;
        // var
        credentialPublicKey: COSEKey;
      };
    };
    fmt: "none";
    attStmt: {};
  } => {
    const decoded = decode(bytes);
    let authData: Uint8Array = decoded.authData;
    const rpIdHash = authData.slice(0, 32);
    const flags = authData.slice(32, 33);
    const signCount = authData.slice(33, 37);
    const attestedCredentialData = authData.slice(37);
    const AAGUID = attestedCredentialData.slice(0, 16);
    const credentialIdLength = attestedCredentialData.slice(16, 18);
    const credentialIdLenghInt = Buffer.from(credentialIdLength).readUIntBE(
      0,
      credentialIdLength.length
    );
    const credentialId = attestedCredentialData.slice(
      18,
      18 + credentialIdLenghInt
    );
    const credentialPublicKey = attestedCredentialData.slice(
      18 + credentialIdLenghInt
    );
  
    return {
      fmt: decoded.fmt,
      attStmt: decoded.attStmt,
      authData: {
        rpIdHash,
        flags,
        signCount,
        attestedCredentialData: {
          AAGUID,
          credentialIdLength,
          credentialId,
          credentialPublicKey: decodeCredentialPublicKey(credentialPublicKey),
          // bech32PublicKey,
      },
    },
  };
};


const assertPublicKeyCredential = (
  credential: Credential | PublicKeyCredential | null
): PublicKeyCredential => {
  if (!credential) throw new Error(`No Credential`);
  if (credential && "rawId" in credential) return credential;
  throw new Error(`Invalid Create Credential`);
};
  


const assertAttestationResponse = (
    response: AuthenticatorResponse | AuthenticatorAttestationResponse
): AuthenticatorAttestationResponse => {
    if (response && "attestationObject" in response) return response;
    throw new Error(`Invalid Attestaion Response`);
};


const assertAssertionResponse = (
    response: AuthenticatorResponse | AuthenticatorAssertionResponse
): AuthenticatorAssertionResponse => {
    if (response && "authenticatorData" in response) return response;
    throw new Error(`Invalid Attestaion Response`);
};


/* const decodeBase64PublicKey = (res: Uint8Array): string => {
    const decoded = decode(res);
    const x : Uint8Array = decoded[-2];
    const y : Uint8Array = decoded[-3];
    const concat = new Uint8Array(x.length + y.length + 1);
    concat.set([0x04], 0);
    concat.set(x, 1);
    concat.set(y, x.length + 1);
    return toBase64(concat);
}; */
