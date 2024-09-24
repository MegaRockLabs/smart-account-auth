import type { WalletClient } from "@cosmos-kit/core";
import type { AminoWallet } from "secretjs/dist/wallet_amino";
import type { Credential, CosmosArbitrary, MsgSignData } from "./types";
import type { AminoMsg, OfflineAminoSigner, StdFee, StdSignDoc } from "@cosmjs/amino"
import { toBase64 } from "@cosmjs/encoding";
import { Keplr } from "@keplr-wallet/types";


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
) : Promise<Credential> => {


    let 
        pubkey : string = "", 
        signature : string = "";
    
    if ("address" in signer && "publicKey" in signer) {
        signerAddress ??= signer.address;
        pubkey = toBase64(signer.publicKey);
    } else {
        console.log("not secret signer")
        if ("getOfflineSignerAmino" in signer) {
            signer = await signer.getOfflineSignerAmino!(chainId);
        }

        if ("getAccounts" in signer) {
            const accounts = await (signer as OfflineAminoSigner).getAccounts();
            const firstAccount = accounts[0];
            signerAddress ??= firstAccount.address;
            pubkey = toBase64(firstAccount.pubkey);
        } else if ("getKey" in signer) {
            const key = await signer.getKey(chainId);
            signerAddress ??= key.bech32Address;
            pubkey = toBase64(key.pubKey);
        } else {
            throw new Error("not suppoerted signer");
        }
    }

    hrp ??= signerAddress.split("1")[0];

    if ("signArbitrary" in signer && signer.signArbitrary) {
        const signResult =  await signer.signArbitrary(chainId, signerAddress, message)
        signature = signResult.signature;
    } else {
        const signResult = await (signer as OfflineAminoSigner)
            .signAmino(signerAddress, getArb36SignDoc(signerAddress, message));
        signature = signResult.signature.signature;
    }

    const cosmos_arbitrary : CosmosArbitrary =  {
        message: typeof message === "string" ? message : toBase64(message),
        pubkey,
        signature,
        hrp,
    }

    return { cosmos_arbitrary }
}