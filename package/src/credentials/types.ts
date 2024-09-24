import type { AminoMsg } from "@cosmjs/amino";
import type { Window as KeplrWindow } from "@keplr-wallet/types";
import type { Eip1193Provider } from "ethers";


export interface EvmCredential {
    message: string;
    signature: string;
    signer: string;
}

export interface CosmosArbitrary {
    message: string;
    pubkey: string;
    signature: string;
    hrp : string
}

export interface ClientData {
    type: string;
    challenge: string;
    origin: string;
    crossOrigin: boolean;
}

export interface PasskeyCredential {
    id: string;
    authenticator_data: string;
    client_data: ClientData;
    signature: string;
    user_handle? : string
    pubkey?: string;
}


export type Credential = 
  { evm: EvmCredential } | 
  { cosmos_arbitrary: CosmosArbitrary } |
  { passkey: PasskeyCredential };



export interface CredentialData {
    credentials     : Credential[];
    with_caller?    : boolean;
    primary_index?  : number;
}



export interface MsgSignData extends AminoMsg {
    readonly type: "sign/MsgSignData";
    readonly value: {
      signer: string;
      data: string;
    };
}




export interface COSEKey {
    //  EC identifier - Taken from the  "COSE Elliptic Curves" registry
    crv: number;
    // x-coordinate
    x: Uint8Array;
    // y-coordinate
    y: Uint8Array;
    privateKey?: Uint8Array;
    // RFC 8152 p 34
    /**
     * Identification of the key type
     * Lookup in COSE Key Common Parameters
     */
    kty: string | number;
    /**
     * Key identification value -- match to kid in message
     */
    kid: Uint8Array;
    /**
     * Key usage restruction to this algorithm
     * Lookup in COSE Algorithms
     */
    alg: COSEAlgorithmIdentifier;
    /**
     * Restrict set of premissible operations
     */
    key_ops: (string | number)[];
    /**
     * Base IV to be xor-ed with Partial IVs
     */
    "Base IV": Uint8Array;
}


export interface CBORSignature {
    readonly authenticatorData: string;
    readonly clientDataJSON: string;
    readonly signature: string;
  }
  

export enum AuthenticatorDataFlags {
    none,
    userPresent = 1 << 0,
    userVerified = 1 << 2,
    backupEligible = 1 << 3,
    backupState = 1 << 4,
    attestedCredIncluded = 1 << 6,
    extensionDataIncluded = 1 << 7
}

export type AttestedCredentialData = {
    authenticatorGuid: Buffer
    credentialID: Buffer
    credentialPubKey: Buffer
}

export type AuthenticatorData = {
    rpIDHash: string
    flags: AuthenticatorDataFlags
    useCount: number
    attestedCredentialData?: AttestedCredentialData
}

interface WindowEthereum extends Eip1193Provider {
    isMetamask?: boolean
}


declare global {
    interface Window extends KeplrWindow {
        ethereum?: WindowEthereum;
    } 
}