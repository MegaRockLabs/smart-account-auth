import type { Eip1193Provider } from "ethers";
import type { Credential, EthPersonalSign } from "./types";

import { fromHex, toBase64, toHex, toUtf8 } from "@cosmjs/encoding";


export const requestEthAcccounts = async (
    methodProvider : Eip1193Provider
) : Promise<string[]> => {
    return methodProvider.request({ method: "eth_requestAccounts" });
}


export const getEthPersonalSignCredential = async (
    methodProvider  : Eip1193Provider,
    message         : string | Uint8Array,
    signerAddress?  : string,
) : Promise<Credential & { eth_personal_sign: EthPersonalSign }> => {

    if (typeof message === "string") {
        message = toUtf8(message);
    }

    if (!signerAddress) {
        const addresses : string[] = await requestEthAcccounts(methodProvider);
        signerAddress = addresses[0];
    }

    const signature : string = await methodProvider.request({
        "method": "personal_sign",
        "params": [toHex(message), signerAddress]
    });

    const sigBytes = fromHex(signature.slice(2));

    return {
        eth_personal_sign: {
            signer: signerAddress,
            signature: toBase64(sigBytes),
            message: toBase64(message)
        }
    }
}
