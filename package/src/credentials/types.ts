import { AminoMsg } from "@cosmjs/amino";

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
    challenge: string;
    origin: string;
    type: string;
    crossOrigin: boolean;
}

export interface PasskeyCredential {
    id: string;
    authenticator_data: string;
    client_data: ClientData;
    signature: string;
    user_handle : string
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