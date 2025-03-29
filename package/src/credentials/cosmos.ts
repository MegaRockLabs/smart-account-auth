import type { WalletClient } from "@cosmos-kit/core";
import type { AminoWallet } from "secretjs/dist/wallet_amino";
import type { Credential, CosmosArbitrary, MsgSignData } from "./types";
import type { AminoMsg, OfflineAminoSigner, StdFee, StdSignDoc } from "@cosmjs/amino"
import { toBase64, toUtf8 } from "@cosmjs/encoding";
import { Keplr } from "@keplr-wallet/types";


const base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;


export const makeSignDoc = (
    msgs: readonly AminoMsg[], 
    fee: StdFee, 
    chainId: string, 
    memo: string | undefined, 
    accountNumber: number | string, 
    sequence: number | string, 
    timeout_height?: bigint
): StdSignDoc => {
    return {
        chain_id: chainId,
        account_number: accountNumber.toString(),
        sequence: sequence.toString(),
        fee: fee,
        msgs: msgs,
        memo: memo || "",
        ...(timeout_height && { timeout_height: timeout_height.toString() }),
    };
}

export const getArb36SignData = (
    signerAddress: string,
    data: string | Uint8Array,
) : MsgSignData => (
    {
        type: "sign/MsgSignData",
        value: {
            signer: signerAddress,
            data: typeof data === "string" ? data : toBase64(data),
        }
    }
)

export const getArb36SignDoc = (
    signerAddress: string,
    data: string | Uint8Array,
) : StdSignDoc => {
    const msg = getArb36SignData(signerAddress, data);
    return makeSignDoc([msg], { gas: "0", amount: [] }, "", "", 0, 0);
}
  


export const getCosmosArbitraryCredential = async (
    signer          :    OfflineAminoSigner | WalletClient | AminoWallet | Keplr,
    chainId         :    string,
    message         :    string | Uint8Array, 
    signerAddress?  :    string,
    hrp?            :    string,
) : Promise<Credential & { cosmos_arbitrary:  CosmosArbitrary } > => {

    let 
        pubkey : string = "", 
        signature : string = "";
    
    if ("address" in signer && "publicKey" in signer) { // AminoWallet
        signerAddress ??= signer.address;
        pubkey = toBase64(signer.publicKey);
    } else if ("getAccounts" in signer) { // OfflineAminoSigner
        const accounts = await (signer as OfflineAminoSigner).getAccounts();
        const firstAccount = accounts[0];
        signerAddress ??= firstAccount.address;
        pubkey = toBase64(firstAccount.pubkey);
    } else if ("getAccount" in signer) { // WalletClient
        const account = await signer.getAccount!(chainId);
        signerAddress ??= account.address;
        pubkey = toBase64(account.pubkey);
    } else if ("getKey" in signer) { // Keplr
        const key = await signer.getKey(chainId);
        signerAddress ??= key.bech32Address;
        pubkey = toBase64(key.pubKey);
    } else {
        throw new Error("not suppoerted signer");
    }

    hrp ??= signerAddress.split("1")[0];

    if ("signArbitrary" in signer && signer.signArbitrary) { // WalletClient + Keplr
        const signResult =  await signer.signArbitrary(chainId, signerAddress, message)
        signature = signResult.signature;
    } else {
        const signResult = await (signer as OfflineAminoSigner) // OfflineAminoSigner + AminoWallet
            .signAmino(signerAddress, getArb36SignDoc(signerAddress, message));
        signature = signResult.signature.signature;
    }


    const cosmos_arbitrary : CosmosArbitrary =  {
        message: typeof message === "string" 
            ? (base64regex.test(message) ? message : toBase64(toUtf8(message))) 
            : toBase64(message),
        pubkey,
        signature,
        hrp,
    }

    return { cosmos_arbitrary }
}