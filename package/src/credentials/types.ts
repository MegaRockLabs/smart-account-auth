import type { AminoMsg } from "@cosmjs/amino";
import type { Window as KeplrWindow } from "@keplr-wallet/types";
import type { Eip1193Provider } from "ethers";


export type DataToSign<M = any> = {
    chain_id: string,
    contract_address: string,
    messages: M[],
    nonce: string
}


export interface EthPersonalSign {
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


export interface RegisterPasskeyParams {
    // syntactic sugar / alias  for using options.rp = { name: ... } |  Default: window.location.hostname
    rpName?                 :      string;
    // syntactic sugar / alias for using options.user.displayName  | Default: same as "name" argument 
    displayName?            :      string;
    // alias for options.authenticatorSelection.authenticatorAttachment
    // Set 'true' for 'cross-platform', 'false' for 'platform' and undefined for 'any'
    crossPlatform?          :      boolean;
    // parameters for saving registered passkeys in the local storage
    localStorage?           :      {
        // name of the local storage key to use: Default: "passkeys"
        key?                    :      string;
        // whether to save the passkey in local storage
        savePublicKey?          :      boolean;
    } | boolean;
    // override any of the navigator raw fields
    options?                :      Partial<PublicKeyCredentialCreationOptions>;
    // controlling signal to abort at any point from outside
    signal?                 :      AbortSignal;
    // whether to show console debug messages
    debug?                  :      boolean;
}


/// Parameters that defines the behaviour of the getPasskeyCredential function
/// By default attempts to request a passkey with a given 'id'
/// If no id is given, tries to load passkeys from local storage and find the one that matches
/// the given parameters
/// If no passkey found with given parameters could be found, attempts to register a new passkey
/// If any of the options are disabled or couldn't be performed

export interface GetPasskeyParams {

    // restrict to usage of a (public key) credential with a specific id
    // syntactic sugar for using options.allowCredentials
    id?                      :      string;

    // enduring that a passkey is stricly a cross-platform  or stricly based on a local platform
    crossPlatform?          :      boolean;
    
    // parameters for usage of local storage in order to request a specifc credential
    // false to disable the usage completely
    localStorage?            :      {
        // name of the local storage key to use: Default: "passkeys"
        key?                 :      string;

        // search or assert based on the public key value  
        pubkey?              :      string;

    } | boolean

    // name for calling registerPasskey function automatically in case a passkey with the given parameters couldn't be found
    registerName?            :      string;
    // challenge to use for the registerPasskey function. Ignored if 'registerName' is not set
    registerChallenge?       :      string | Uint8Array;
    // parametes to pass the registerPasskey function. Ignored if 'registerName' is not set
    registerParams?          :      RegisterPasskeyParams;
    // a function to call while awaiting for registration
    registrationCallback?    :      (passkey: Promise<PasskeyInfo>) => void;
    // override any of the navigator raw fields
    options?                 :      Partial<PublicKeyCredentialRequestOptions>;
    // controlling signal to abort at any point from outside
    signal?                  :      AbortSignal;
    // whether to show console debug messages
    debug?                   :      boolean;
}


/* 
export const getPasskeyCredential = async (
    challenge        :  string | Uint8Array,
    id?              :  string,
    pubkey?          :  string,
    options?         :  PublicKeyCredentialRequestOptions,
    loadFromStorage  :  boolean | string = true,
    name?            :  string,
) */




export interface PasskeyInfo {
    id: string;
    origin: string;
    publicKey?: string;
    crossPlatform?: boolean;
    userHandle?: string;
}


export type Credential = 
  { eth_personal_sign: EthPersonalSign } | 
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