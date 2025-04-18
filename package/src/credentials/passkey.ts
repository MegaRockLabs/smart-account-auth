import type { Credential as AuthCredential, ClientData, PasskeyCredential, RegisterPasskeyParams, PasskeyInfo, GetPasskeyParams } from "./types";
import { decode } from "cbor-x";
import { v4 } from "uuid";

import { COSEKey } from "./types";
import { fromUtf8, toBase64, toUtf8 } from "@cosmjs/encoding";
//import { random_32 } from "@solar-republic/neutrino";


export const random_32 = () => crypto.getRandomValues(new Uint8Array(32));



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


let CACHED : Record<string, PasskeyInfo> | undefined = undefined;

export const loadPasskeysFromStorage = (
  storageKey: string = "passkeys"
) : Record<string, PasskeyInfo> => {
  if (CACHED) return CACHED;
  const storageObject = localStorage.getItem(storageKey) || "{}";
  const passkeys = JSON.parse(storageObject) as Record<string, PasskeyInfo>;
  CACHED = passkeys;
  return passkeys;
}


export const loadPasskeyById = (
  id: string,
  storageKey: string = "passkeys"
) : PasskeyInfo | undefined => {
  const passkeys = loadPasskeysFromStorage(storageKey);
  return passkeys[id];
}


export const registerPasskey = async (
    name                  :   string,
    challenge?            :   string | Uint8Array,
    params?               :   RegisterPasskeyParams
) : Promise<PasskeyInfo> => {

  params = params || {};

  if (challenge) {
      challenge = typeof challenge === "string" ? toUtf8(challenge) : challenge
  } else {
      challenge = random_32();
  }

  const rp  = { name: params.rpName ?? window.location.hostname ?? "localhost" };

  const debug = params.debug ?? false;
  const displayName = params.displayName ?? name;

  const user = {
    id: new Uint8Array(Buffer.from(v4())),
    displayName,
    name,
  }

  if (debug) {
    console.log("Passkey Register RP", rp);
    console.log("Passkey Register User", user);
  }

  const authenticatorSelection : AuthenticatorSelectionCriteria = {
    requireResidentKey: false,
    userVerification: "preferred",
  }

  if (params.crossPlatform != undefined) {
    authenticatorSelection.authenticatorAttachment = params.crossPlatform ? "cross-platform" : "platform";
  }

  const createOptions : CredentialCreationOptions = {
    publicKey: {
      rp,
      user,
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      challenge,
      timeout: 60000,
      excludeCredentials: [],
      authenticatorSelection,
      ...(params.options ?? {}),
    },
    signal: params.signal
  };

  if (debug) {
    console.log("Passkey Create Options", createOptions);
  }

  const credential = await navigator.credentials.create(createOptions);
  const createCredential = assertPublicKeyCredential(credential);
  const attestationResponse = assertAttestationResponse(createCredential.response);
  const decoded = decodeAttestationObject(new Uint8Array(attestationResponse.attestationObject));

  if (debug) {
    console.log("Credential", createCredential);
    console.log("PublicKeyCredential", createCredential);
    createCredential.authenticatorAttachment
    console.log("Attestation Response", attestationResponse);
    console.log("Decoded Attestation Object", decoded);
  }

  const publicKey = getBase64PublicKey(decoded.authData.attestedCredentialData.credentialPublicKey);

  let newPassKey : PasskeyInfo = { 
      id: toBase64(decoded.authData.attestedCredentialData.credentialId),
      userHandle: user.displayName ?? user.name,
      origin,
  };

  if (createCredential.authenticatorAttachment) {
    newPassKey.crossPlatform = createCredential.authenticatorAttachment === "cross-platform";
  } else if (params.crossPlatform != undefined) {
    newPassKey.crossPlatform = params.crossPlatform;
  }

  if (params.localStorage != false) {
    const [storageKey, savePublicKey] = typeof params.localStorage === "object"
      ? [params.localStorage.key ?? "passkeys", params.localStorage.savePublicKey ?? true]
      : ["passkeys", true];

    if (savePublicKey) {
      newPassKey.publicKey = publicKey;
    }
    // check for existing keys
    const stored = localStorage.getItem(storageKey) || "{}";
    const passkeys = JSON.parse(stored) as Record<string, PasskeyInfo>;

    passkeys[newPassKey.id] = newPassKey;
    localStorage.setItem(storageKey, JSON.stringify(passkeys));
    CACHED = passkeys;
  }

  newPassKey.publicKey = publicKey;

  if (debug) {
    console.log("Passkey Created", newPassKey);
  }

  return newPassKey;
}

/// Parameters that defines the behaviour of the getPasskeyCredential function
/// By default attempts to request a passkey with a given 'id'
/// If no id is given, tries to load passkeys from local storage and find the one that matches
/// the given parameters
/// If no passkey found with given parameters could be found, attempts to register a new passkey if given a name
export const getPasskeyCredential = async (
    challenge        :  string | Uint8Array,
    params?          :  GetPasskeyParams
) : Promise<AuthCredential & { passkey: PasskeyCredential }>  => {
    params = params || {};
    challenge = typeof challenge === "string" ? toUtf8(challenge) : challenge

    let id = params.id;
    const debug = params.debug ?? false;

    let
      found: PasskeyInfo[] = [],
      pubkey: string | undefined = undefined,
      passkeys: Record<string, PasskeyInfo> = {},
      error : string = "";

    if (params.localStorage != false) {
      const storageParams = typeof params.localStorage === "object" ? params.localStorage : {};
      passkeys = loadPasskeysFromStorage(storageParams.key ?? "passkeys")

      if (debug) {
        console.log("LocalStorage Passkeys Found", passkeys);
      }
      if (id) {
        const pk = passkeys[id] ?? passkeys[urlToBase64(id)];
        if (!pk) {
          error = `No stored Passkeys with given ID`; 
        } else if (storageParams.pubkey && pk.publicKey !== pk.publicKey) {
          error = `No Passkey with the given public key could be found`;
        } else if (params.crossPlatform != undefined && pk.crossPlatform !== params.crossPlatform) {
          error = `Requested passkey has a different crossPlatform flag than the requested one`;
        } else {
          id = pk.id;
          pubkey = pk.publicKey;
        }
      } else {
        const keys = Object.values(passkeys);
        const values = Object.values(passkeys);
        if (keys.length === 0) {
          error = `No Passkeys Found and automatic registration is disabled`;
        } else if (storageParams.pubkey) {
          const foundOne = values.find((p) => p.publicKey === storageParams.pubkey);
          if (!foundOne) {
            error = `No Passkey with the given public key could be found`;
          } else {
            id = foundOne.id;
            pubkey = foundOne.publicKey;
          }
        } else if (params.crossPlatform !== undefined) {
          found = values.filter((p) => p.crossPlatform === params.crossPlatform);
          if (found.length == 0) {
            error = `No Passkey with the given crossPlatform flag could be found`;
          }
        } else {
          found = values;
        }
      }
    }

    if (debug) {
      console.log("Passkey ID", id);
      console.log("Passkey Public Key", pubkey);
      console.log("Passkey Filter Found", found);
      console.log("Passkey Error", error);
    }

    if (error && params.registerName) {
      const registrationPromise = registerPasskey(
        params.registerName, 
        params.registerChallenge, 
        { 
          debug,
          crossPlatform: params.crossPlatform,
          ...params.registerParams, 
        }
      );
      if (params.registrationCallback) {
        params.registrationCallback(registrationPromise);
      }
      const registration = await registrationPromise;
      id = registration.id;
      pubkey = registration.publicKey;
      if (debug) {
        console.log("Passkey Registration", registration);
      }
      error = "";
    } 

    if (error) {
      throw new Error(error);
    }
    
    let allowCredentials : PublicKeyCredentialDescriptor[] = [];
    if (found.length > 0) {
      allowCredentials = found.map((p) => ({id: Buffer.from(p.id, "base64"), type: "public-key"}));
    } else if (id) {
      allowCredentials.push({id: Buffer.from(id, "base64"), type: "public-key"});
    }
        
    const credentialRequestOptions: CredentialRequestOptions = {
        publicKey: {
            allowCredentials,
            challenge,
            timeout: 60000,
            ...(params.options ?? {})
        },
    };

    if (debug) {
      console.log("Passkey Request Options", credentialRequestOptions);
    }

    const credential = await navigator.credentials.get(credentialRequestOptions);
    if (!credential) {
      throw new Error(`Couldn't get a credential`);
    } else {
      id = credential.id;
    }

    const getCredential = assertPublicKeyCredential(credential);
    const response = assertAssertionResponse(getCredential.response);
    const client_data : ClientData = JSON.parse(fromUtf8(new Uint8Array(response.clientDataJSON))) as ClientData

    if (debug) {
      console.log("Passkey Request Credential", getCredential);
      console.log("Passkey Request Asserted Response", response);
      console.log("Passkey Request Client Data", client_data);
    }

    client_data.challenge = urlToBase64(client_data.challenge);
    if (!pubkey) pubkey = (passkeys[id] ?? passkeys[urlToBase64(id)])?.publicKey;

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
