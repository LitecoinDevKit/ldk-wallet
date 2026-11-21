// Kept free of DOM and imports: `scripts/action-flags.test.mjs` loads this file
// in Node to check that backend action flags map to the expected UI controls.

/** Which self-spend buttons the backend allows. The UI never works this out itself. */
export type ChurnActions = {
  retry: boolean;
  cancel: boolean;
  open_settings: boolean;
};

export type ChurnPhase =
  | "waiting-to-broadcast"
  | "waiting-for-cover"
  | "waiting-confirm"
  | "paused-solo"
  | "paused-unscored"
  | "done"
  | "cancelled";

export type ChurnPending = "retry" | "cancel" | null;

export type ChurnActionButton = {
  id: "retry" | "open-settings" | "cancel";
  label: "Try again" | "Open Settings" | "Cancel";
  kind: "primary" | "ghost";
  disabled: boolean;
};

/** One status per coin, picked by `coin_status` / `public_coin_status` in the backend. */
export type CoinStatus =
  | "churning"
  | "sending"
  | "pending"
  | "maturing"
  | "frozen"
  | "tied-to-pegin"
  | "ready";

/** Why a coin's spend buttons are off. */
export type CoinBlock =
  | { kind: "churning" }
  | { kind: "sending" }
  | { kind: "frozen" }
  | { kind: "unconfirmed" }
  | { kind: "maturing"; blocks_left: number };

/** Which coin buttons the backend allows. The UI never works this out itself. */
export type CoinActions = {
  spend_to_self: boolean;
  split: boolean;
  transfer: boolean;
  select: boolean;
  freeze: boolean;
  unfreeze: boolean;
  blocked: CoinBlock | null;
};

export type SplitChain = "public" | "private";

export type CoinButton = "split" | "transfer" | "spend";

export type CoinButtonSpec = {
  disabled: boolean;
  title: string;
};

export type FreezeButtonSpec = CoinButtonSpec & {
  label: "Freeze" | "Unfreeze";
  targetLocked: boolean | null;
};

export type SpendToSelfButtonSpec = {
  visible: boolean;
  label: "Spend to self";
  kind: "primary" | "ghost";
  title: string;
};

export type CoinActionState = {
  jobHolds: boolean;
  spendToSelf: SpendToSelfButtonSpec;
  freeze: FreezeButtonSpec;
  split: CoinButtonSpec;
  transfer: CoinButtonSpec;
  select: CoinButtonSpec;
};

const COIN_BLOCKED_COPY: Record<CoinButton, { frozen: string; unconfirmed: string }> = {
  split: { frozen: "Unfreeze to split.", unconfirmed: "Cannot spend privately until confirmed." },
  transfer: { frozen: "Unfreeze to transfer.", unconfirmed: "Cannot transfer until confirmed." },
  spend: { frozen: "Unfreeze to spend.", unconfirmed: "Cannot spend privately until confirmed." },
};

const PUBLIC_COIN_BLOCKED_COPY: Record<CoinButton, { frozen: string; unconfirmed: string }> = {
  split: { frozen: "Unfreeze to split.", unconfirmed: "Split is disabled until the coin is confirmed." },
  transfer: {
    frozen: "Unfreeze to transfer.",
    unconfirmed: "Transfer is disabled until the coin is confirmed.",
  },
  spend: { frozen: "Unfreeze to spend.", unconfirmed: "Cannot spend until confirmed." },
};

export function churnPhaseActive(phase: ChurnPhase | null | undefined): boolean {
  return (
    phase === "waiting-to-broadcast" ||
    phase === "waiting-for-cover" ||
    phase === "waiting-confirm" ||
    phase === "paused-solo" ||
    phase === "paused-unscored"
  );
}

/** Map backend `churn_actions` flags directly to the self-spend card's buttons. */
export function churnActionButtons(
  actions: ChurnActions | null | undefined,
  pending: ChurnPending = null,
): ChurnActionButton[] {
  if (!actions) return [];
  const disabled = pending != null;
  const out: ChurnActionButton[] = [];
  if (actions.retry) {
    out.push({ id: "retry", label: "Try again", kind: "primary", disabled });
  }
  if (actions.open_settings) {
    out.push({ id: "open-settings", label: "Open Settings", kind: "primary", disabled });
  }
  if (actions.cancel) {
    out.push({ id: "cancel", label: "Cancel", kind: "ghost", disabled });
  }
  return out;
}

/** Tooltip for a coin button the backend turned off. */
export function coinBlockedTitle(
  blocked: CoinBlock | null,
  button: CoinButton,
  chain: SplitChain = "private",
): string {
  const copy = chain === "public" ? PUBLIC_COIN_BLOCKED_COPY[button] : COIN_BLOCKED_COPY[button];
  switch (blocked?.kind) {
    case "churning":
      return "A self-spend has this coin.";
    case "sending":
      return "A send is still using this coin.";
    case "frozen":
      return copy.frozen;
    case "maturing":
      return `Matures in ${blocked.blocks_left} block${blocked.blocks_left === 1 ? "" : "s"}.`;
    default:
      return copy.unconfirmed;
  }
}

export function freezeLabel(actions: Pick<CoinActions, "unfreeze">): "Freeze" | "Unfreeze" {
  return actions.unfreeze ? "Unfreeze" : "Freeze";
}

/**
 * Target `locked` state for a freeze/unfreeze command, derived solely from
 * `actions.freeze` and `actions.unfreeze` (never from `coin.locked`).
 */
export function freezeTargetLocked(
  actions: Pick<CoinActions, "freeze" | "unfreeze">,
): boolean | null {
  if (actions.freeze && !actions.unfreeze) return true;
  if (actions.unfreeze && !actions.freeze) return false;
  return null;
}

function buildFreezeSpec(actions: CoinActions, chain: SplitChain): FreezeButtonSpec {
  const targetLocked = freezeTargetLocked(actions);
  const disabled = targetLocked == null;
  return {
    label: freezeLabel(actions),
    disabled,
    title: disabled ? coinBlockedTitle(actions.blocked, "spend", chain) : "",
    targetLocked,
  };
}

/** Pure button and checkbox state for a private coin row / picker entry. */
export function privateCoinActionState(
  coin: { status: CoinStatus; actions: CoinActions },
  opts?: { hasOtherWallets?: boolean; inFlightSpend?: boolean },
): CoinActionState {
  const hasOtherWallets = opts?.hasOtherWallets === true;
  const inFlightSpend = opts?.inFlightSpend === true;
  const jobHolds =
    coin.status === "churning" || coin.status === "sending" || inFlightSpend;
  const { actions } = coin;
  const canTransfer = hasOtherWallets && actions.transfer;
  return {
    jobHolds,
    spendToSelf: {
      visible: !jobHolds && actions.spend_to_self,
      label: "Spend to self",
      kind: coin.status === "tied-to-pegin" ? "primary" : "ghost",
      title: "Spend this coin to an address of this wallet",
    },
    freeze: buildFreezeSpec(actions, "private"),
    split: {
      disabled: !actions.split,
      title: actions.split
        ? "Split this private coin into multiple outputs"
        : coinBlockedTitle(actions.blocked, "split", "private"),
    },
    transfer: {
      disabled: !canTransfer,
      title: !actions.transfer
        ? coinBlockedTitle(actions.blocked, "transfer", "private")
        : !hasOtherWallets
          ? "Add another wallet to transfer coins between them."
          : "Send this coin to another wallet on this device",
    },
    select: {
      disabled: !actions.select,
      title: actions.select
        ? "Include this coin"
        : coinBlockedTitle(actions.blocked, "spend", "private"),
    },
  };
}

/** Pure button and checkbox state for a public coin row / picker entry. */
export function publicCoinActionState(
  utxo: { status: CoinStatus; actions: CoinActions },
  opts?: { hasOtherWallets?: boolean; inFlightSpend?: boolean },
): CoinActionState {
  const hasOtherWallets = opts?.hasOtherWallets === true;
  const inFlightSpend = opts?.inFlightSpend === true;
  const { actions } = utxo;
  const canTransfer = hasOtherWallets && actions.transfer;
  return {
    jobHolds: inFlightSpend,
    spendToSelf: {
      visible: false,
      label: "Spend to self",
      kind: "ghost",
      title: "Spend this coin to an address of this wallet",
    },
    freeze: buildFreezeSpec(actions, "public"),
    split: {
      disabled: !actions.split,
      title: actions.split
        ? "Split this coin into multiple outputs"
        : coinBlockedTitle(actions.blocked, "split", "public"),
    },
    transfer: {
      disabled: !canTransfer,
      title: !actions.transfer
        ? coinBlockedTitle(actions.blocked, "transfer", "public")
        : !hasOtherWallets
          ? "Add another wallet to transfer coins between them."
          : "Send this coin to another wallet on this device",
    },
    select: {
      disabled: !actions.select,
      title: actions.select
        ? "Include this coin"
        : coinBlockedTitle(actions.blocked, "spend", "public"),
    },
  };
}
