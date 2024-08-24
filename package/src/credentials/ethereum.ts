import type { Eip1193Provider } from "ethers";
import type { Credential } from "./types";

import { fromHex, toBase64, toHex, toUtf8 } from "@cosmjs/encoding";


export const getEthPersonalCredential = async (
    methodProvider  : Eip1193Provider,
    message         : string | Uint8Array,
    signerAddress?  : string,
) : Promise<Credential>  => {

    if (typeof message === "string") {
        message = toUtf8(message);
    }

    if (!signerAddress) {
        const addresses : string[] = await methodProvider.request({ method: "eth_requestAccounts" });
        signerAddress = addresses[0];
    }

    const signature : string = await methodProvider.request({
        "method": "personal_sign",
        "params": [toHex(message), signerAddress]
    });

    const hex = fromHex(signature.slice(2));

    return {
        evm: {
            signer: signerAddress,
            signature: toBase64(hex),
            message: toBase64(message)
        }
    }
}
