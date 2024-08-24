import type { Credential as AuthCredential, ClientData } from "./types";
import { toUtf8 } from "secretjs";
import { v4 } from "uuid";
import { decode } from "cbor-x";

import { random_32 } from "@solar-republic/neutrino";
import { fromUtf8, toBase64 } from "@cosmjs/encoding";
import { COSEKey } from "./types";


export const registerPasskey = async (
    name                  :   string,
    rp?                   :   PublicKeyCredentialRpEntity,
    challenge?            :   string | Uint8Array,
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
        const wrapper = saveToLocalStorage === true ? "passkeys" : saveToLocalStorage;
        const passkeys = localStorage.getItem(wrapper) || "{}";
        const parsed = JSON.parse(passkeys) as Record<string, string>;
        parsed[registered.id] = registered.pubkey;
        localStorage.setItem(wrapper, JSON.stringify(parsed));
    }   

    return registered;
}



export const getPasskeyCredential = async (
    message       :  string | Uint8Array,
    id            :  string,
    options?      :  PublicKeyCredentialRequestOptions,
    pubkey?       :  string,
) : Promise<AuthCredential>  => {

    const challenge = typeof message === "string" ? toUtf8(message) : message

    const credentialRequestOptions: CredentialRequestOptions = {
        publicKey: {
            allowCredentials: [
                {
                    id: Buffer.from(id, "base64"),
                    type: "public-key",
                },
            ],
            challenge,
            timeout: 60000,
            ...options
        },
    };

    const credential = await navigator.credentials.get(credentialRequestOptions);
    const getCredential = assertPublicKeyCredential(credential);
    const response = assertAssertionResponse(getCredential.response);


    const cred : AuthCredential = {
        passkey: {
            id,
            signature: toBase64(new Uint8Array(response.signature)),
            authenticator_data: toBase64(new Uint8Array(response.authenticatorData)),
            client_data: JSON.parse(fromUtf8(new Uint8Array(response.clientDataJSON))) as ClientData,
            pubkey
        }
    }
    return cred;
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
