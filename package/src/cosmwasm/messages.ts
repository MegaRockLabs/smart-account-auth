import type { Coin } from "@keplr-wallet/types"

export type CosmosMsg = 
    BankMsg | StakingMsg | GovMsg | WasmMsg | IbcMsg;


export type BankMsg = {
    bank:  SendCoins | BurnCoins;
}

export type StakingMsg = {
    staking: Delegate | Undelegate | Redelegate;
}

export type GovMsg = {
    gov: {
        vote: {
            proposal_id: number;
            vote: VoteOption;
        };
    }
};

export type WasmMsg = {
    wasm: {
        execute: {
            contract_addr: string;
            funds: Coin[];
            msg: string;
          };
    }
}

export type IbcMsg = {
    transfer: {
      amount: Coin;
      channel_id: string;
      timeout: IbcTimeout;
      to_address: string;
    };
  }


export type SendCoins = {
    send: {
        amount: Coin[];
        to_address: string;
    };
};

export type BurnCoins = {
    burn: {
        amount: Coin[];
    };
};



export type Delegate = {
    delegate: {
        amount: Coin;
        validator: string;
    };
};

export type Undelegate = {
    undelegate: {
        amount: Coin;
        validator: string;
    };
};

export type Redelegate = {
    amount: Coin;
    dst_validator: string;
    src_validator: string;
}


export type VoteOption = "yes" | "no" | "abstain" | "no_with_veto";

export type IbcTimeout = {
    block?: IbcTimeoutBlock;
    timestamp?: string;
}

export type IbcTimeoutBlock = {
    height: number;
    revision: number;
}

