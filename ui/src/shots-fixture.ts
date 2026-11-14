/**
 * Sample wallet for `?shots=1`. Addresses and amounts are documentation data.
 * Nothing here is read from a wallet on disk.
 *
 * Scenes (`?shots=1&scene=`):
 * - balance (default): two balances, a quiet sheet, status strip with an age
 * - coins: Private list with frozen, labeled, maturing, and peg-in-tied rows
 * - self-spend: that list, plus one row after a scored hop (shared-block depth)
 * - recovery: no wallet yet, so boot stays on create / restore
 *
 * `cover=no-rpc`, `cover=waiting`, or `cover=spreading` marks one private coin as
 * waiting for cover so the live card can be checked without a node. `cover=solo`
 * marks a quiet block. `cover=sending` shows one private and one public coin held by a
 * broadcast in flight. `rpc=1` pretends a Litecoin RPC URL is saved.
 */

type Scene = "balance" | "coins" | "self-spend" | "recovery";

const TIP = 3_104_218;
const S = {
  p40: 40_000_000,
  p75: 75_000_000,
  p80: 80_000_000,
  p115: 115_000_000,
  p120: 120_000_000,
  p200: 200_000_000,
  p210: 210_000_000,
  p240: 240_000_000,
  p1000: 1_000_000_000,
  p1240: 1_240_000_000,
} as const;

const PUBLIC_ADDRESS = "ltc1qsampledata0000000000000000000000qqqq";
const PRIVATE_ADDRESS =
  "ltcmweb1qqsampledata000000000000000000000000000000000000000000000000";

function scene(): Scene {
  const raw = new URLSearchParams(window.location.search).get("scene");
  if (raw === "coins" || raw === "self-spend" || raw === "recovery") return raw;
  return "balance";
}

function tipTime(): number {
  // Stay inside the "1 minute" bucket (60–119 seconds) for the length of a capture.
  return Math.floor(Date.now() / 1000) - 90;
}

function id(prefix: string): string {
  const alphabet = "0123456789abcdef";
  let out = prefix;
  let n = prefix.length;
  while (out.length < 64) {
    out += alphabet[n % alphabet.length];
    n += 3;
  }
  return out.slice(0, 64);
}

function summary(immaturePrivate: number, confirmedPrivate: number) {
  const transparent = {
    network: "mainnet" as const,
    confirmed_sats: S.p1240,
    trusted_pending_sats: 0,
    untrusted_pending_sats: 0,
    immature_sats: 0,
    total_sats: S.p1240,
    tip_height: TIP,
    tip_time: tipTime(),
    receive_address: PUBLIC_ADDRESS,
  };
  return {
    transparent,
    confirmedPrivate,
    immaturePrivate,
  };
}

function combined() {
  const coins = privateCoins();
  const immature = coins
    .filter((coin) => !coin.mature)
    .reduce((sum, coin) => sum + coin.amount_sats, 0);
  const confirmed = coins
    .filter((coin) => coin.mature)
    .reduce((sum, coin) => sum + coin.amount_sats, 0);
  const parts = summary(immature, confirmed);
  return {
    transparent: parts.transparent,
    mweb_confirmed_sats: confirmed,
    mweb_unconfirmed_sats: 0,
    mweb_immature_sats: immature,
    mweb_maturity_blocks: 6,
    mweb_total_sats: confirmed + immature,
    mweb_receive_address: PRIVATE_ADDRESS,
    mweb_synced_height: TIP,
    mweb_stale: false,
    mweb_status: "synced",
  };
}

type Coin = {
  output_id: string;
  amount_sats: number;
  confirmations: number;
  mature: boolean;
  maturity_blocks_left?: number;
  locked?: boolean;
  label?: string;
  from_pegin?: boolean;
  non_solo_blocks?: number | null;
  last_other_kernels?: number | null;
  last_other_outputs?: number | null;
  hops?: { other_kernels: number; other_outputs: number }[];
  churn_phase?: string | null;
  churn_cover_hold?: "no-rpc" | "waiting" | null;
  churn_cover_min?: number | null;
  churn_cover_seen?: number | null;
  churn_cover_checked_at?: number | null;
  churn_cover_total?: number | null;
  churn_cover_kernels?: number | null;
  churn_cover_outputs?: number | null;
  churn_cover_error?: string | null;
  churn_spreading?: boolean | null;
  churn_target?: number | null;
  churn_counted?: number | null;
  churn_actions?: { retry: boolean; cancel: boolean; open_settings: boolean } | null;
  churn_error?: string | null;
  status: string;
  actions: CoinActions;
};

type CoinActions = {
  spend_to_self: boolean;
  split: boolean;
  transfer: boolean;
  select: boolean;
  freeze: boolean;
  unfreeze: boolean;
  blocked: { kind: string; blocks_left?: number } | null;
};

const READY: CoinActions = {
  spend_to_self: true,
  split: true,
  transfer: true,
  select: true,
  freeze: true,
  unfreeze: false,
  blocked: null,
};

function blockedActions(blocked: CoinActions["blocked"], unfreeze = false): CoinActions {
  return {
    spend_to_self: false,
    split: false,
    transfer: false,
    select: false,
    freeze: false,
    unfreeze,
    blocked,
  };
}

function quietCoin(partial: Omit<Coin, "status" | "actions"> & Partial<Coin>): Coin {
  return {
    from_pegin: false,
    non_solo_blocks: 0,
    status: "ready",
    actions: READY,
    ...partial,
  };
}

function holdForChurn(coin: Coin) {
  coin.locked = true;
  coin.status = "churning";
  coin.actions = blockedActions({ kind: "churning" });
}

function privateCoins(): Coin[] {
  const frozen = quietCoin({
    output_id: id("a1"),
    amount_sats: S.p120,
    confirmations: 40,
    mature: true,
    locked: true,
    status: "frozen",
    actions: blockedActions({ kind: "frozen" }, true),
  });
  const labeled = quietCoin({
    output_id: id("b2"),
    amount_sats: S.p80,
    confirmations: 120,
    mature: true,
    label: "Savings",
  });
  const maturing: Coin = {
    output_id: id("c3"),
    amount_sats: S.p40,
    confirmations: 2,
    mature: false,
    maturity_blocks_left: 4,
    from_pegin: false,
    non_solo_blocks: 0,
    status: "maturing",
    actions: blockedActions({ kind: "maturing", blocks_left: 4 }),
  };
  const tied: Coin = {
    output_id: id("t7"),
    amount_sats: S.p75,
    confirmations: 30,
    mature: true,
    from_pegin: true,
    non_solo_blocks: 0,
    label: "From peg-in",
    status: "tied-to-pegin",
    actions: READY,
  };
  const current = scene();
  const cover = new URLSearchParams(window.location.search).get("cover");
  if (cover === "solo" && current !== "recovery" && current !== "balance") {
    tied.churn_phase = "paused-solo";
    tied.churn_actions = { retry: true, cancel: true, open_settings: false };
    tied.churn_target = 1;
    tied.churn_counted = 0;
    holdForChurn(tied);
  } else if (cover === "spent" && current !== "recovery" && current !== "balance") {
    tied.churn_phase = "waiting-for-cover";
    tied.churn_error = "This coin was spent by another transaction.";
    tied.churn_actions = { retry: false, cancel: true, open_settings: false };
    tied.churn_target = 1;
    tied.churn_counted = 0;
    holdForChurn(tied);
  } else if (
    (cover === "no-rpc" || cover === "waiting" || cover === "spreading") &&
    current !== "recovery" &&
    current !== "balance"
  ) {
    tied.churn_phase = "waiting-for-cover";
    tied.churn_cover_hold = cover === "no-rpc" ? "no-rpc" : "waiting";
    tied.churn_actions = { retry: false, cancel: true, open_settings: cover === "no-rpc" };
    tied.churn_target = 3;
    tied.churn_counted = 1;
    holdForChurn(tied);
    const checkedAt = Math.floor(Date.now() / 1000) - 40;
    if (cover === "waiting") {
      tied.churn_cover_min = 2;
      tied.churn_cover_seen = 1;
      tied.churn_cover_checked_at = checkedAt;
      tied.churn_cover_total = 309;
      tied.churn_cover_kernels = 1;
      tied.churn_cover_outputs = 2;
    } else if (cover === "spreading") {
      tied.churn_cover_min = 2;
      tied.churn_cover_seen = 3;
      tied.churn_cover_checked_at = checkedAt;
      tied.churn_cover_total = 412;
      tied.churn_cover_kernels = 3;
      tied.churn_cover_outputs = 5;
      tied.churn_spreading = true;
    }
  } else if (cover === "sending" && current !== "recovery" && current !== "balance") {
    labeled.status = "sending";
    labeled.actions = blockedActions({ kind: "sending" });
  }
  if (current === "balance") {
    return [
      quietCoin({
        output_id: id("d4"),
        amount_sats: S.p200,
        confirmations: 80,
        mature: true,
      }),
      quietCoin({
        output_id: id("e5"),
        amount_sats: S.p115,
        confirmations: 22,
        mature: true,
      }),
    ];
  }
  const scored = quietCoin({
    output_id: id("f6"),
    amount_sats: S.p210,
    confirmations: 18,
    mature: true,
    label: "Travel",
    non_solo_blocks: 1,
    last_other_kernels: 4,
    last_other_outputs: 7,
    hops: [{ other_kernels: 4, other_outputs: 7 }],
    churn_phase: "done",
  });
  const ordinary = quietCoin({
    output_id: id("g8"),
    amount_sats: S.p75,
    confirmations: 30,
    mature: true,
  });
  if (current === "self-spend") return [scored, tied, frozen, labeled, maturing];
  return [tied, frozen, labeled, maturing, ordinary];
}

function transactions() {
  const now = Math.floor(Date.now() / 1000);
  return [
    {
      txid: id("11"),
      net_sats: S.p40,
      sent_sats: 0,
      received_sats: S.p40,
      fee_sats: 5000,
      height: TIP - 20,
      confirmations: 20,
      timestamp: now - 3600,
      kind: "pegin",
    },
    {
      txid: id("22"),
      net_sats: S.p200,
      sent_sats: 0,
      received_sats: S.p200,
      fee_sats: null,
      height: TIP - 8,
      confirmations: 8,
      timestamp: now - 7200,
      kind: "transparent",
    },
  ];
}

function settings() {
  return {
    electrum_url: "ssl://electrum.example.com:50002",
    electrum_validate_domain: true,
    electrum_use_public_fallback: true,
    auto_lock_minutes: 15,
    electrum_active_url: "ssl://electrum.example.com:50002",
    litecoin_rpc_url: new URLSearchParams(window.location.search).get("rpc") === "1"
      ? "http://127.0.0.1:9332"
      : null,
    broadcast_via_own_node: false,
    mweb_peers: ["peer.example.com:9333"],
    mweb_scheme: "litecoin-core",
    explorer_base_url: "https://litview.space",
    show_fiat: true,
    use_explorer_fee_hints: true,
    insights_enabled: true,
  };
}

function pulse() {
  return {
    // The explorer trails Electrum by a block; the UI should still show TIP.
    tip_height: TIP - 1,
    price_usd: 84.2,
    price_change_pct: 1.2,
    fastest_fee_sat_vb: 3,
    half_hour_fee_sat_vb: 2,
    mempool_tx_count: 1280,
    mempool_vsize: 450_000,
    fetched_at_unix: Math.floor(Date.now() / 1000),
  };
}

function series(
  idName: string,
  title: string,
  unit: string,
  values: number[],
  change: number,
) {
  return {
    id: idName,
    title,
    unit,
    index: "daily",
    values,
    latest: values[values.length - 1] ?? null,
    change_pct: change,
    litview_path: "/charts",
  };
}

function wave(start: number, step: number, count = 30): number[] {
  return Array.from({ length: count }, (_, i) => start + Math.sin(i / 4) * step + i * (step / 20));
}

function charts() {
  return [
    series("price", "Price", "usd", wave(80, 3), 1.4),
    series("fee_median", "Median fee", "sats", wave(120, 40), -2.1),
    series("hash_rate", "Hash rate", "h", wave(1.2e15, 0.05e15), 0.6),
  ];
}

function litvmSummary() {
  return {
    address: "0x1111111111111111111111111111111111111111",
    balance_zkltc: "12.5",
    network_id: "liteforge",
    network_name: "LiteForge",
    chain_id: 4441,
    symbol: "zkLTC",
    faucet_url: "https://testnet.litvm.com",
    explorer: "https://explorer.example.com",
    rpc_http: "https://liteforge.example.com",
    signing_enabled: true,
    seed_note: null,
  };
}

function litvmHistory() {
  const now = Math.floor(Date.now() / 1000);
  return {
    txs: [
      {
        txid: id("aa"),
        from: "0x2222222222222222222222222222222222222222",
        to: "0x1111111111111111111111111111111111111111",
        amount_zkltc: "10",
        incoming: true,
        pending: false,
        failed: false,
        nonce: 1,
        timestamp: now - 86_400,
      },
      {
        txid: id("bb"),
        from: "0x1111111111111111111111111111111111111111",
        to: "0x3333333333333333333333333333333333333333",
        amount_zkltc: "1.5",
        incoming: false,
        pending: false,
        failed: false,
        nonce: 2,
        timestamp: now - 3_600,
      },
    ],
    warning: null,
  };
}

type Args = Record<string, unknown> | undefined;

/** The sheet's own request, so the preview echoes what the user picked. */
function churnRequest(args: Args): { cover_min: number; spread_send: boolean } {
  const req = (args?.req ?? {}) as { cover_min?: number; spread_send?: boolean };
  return {
    cover_min: req.cover_min && req.cover_min > 0 ? req.cover_min : 2,
    spread_send: req.spread_send === true,
  };
}

const PUBLIC_READY: CoinActions = { ...READY, spend_to_self: false };

function publicCoins() {
  const sending =
    new URLSearchParams(window.location.search).get("cover") === "sending" &&
    scene() !== "recovery" &&
    scene() !== "balance";
  return [
    {
      outpoint: `${id("91")}:0`,
      txid: id("91"),
      vout: 0,
      amount_sats: S.p1000,
      keychain: "external",
      confirmations: 12,
      locked: false,
      status: "ready",
      actions: PUBLIC_READY,
    },
    {
      outpoint: `${id("92")}:1`,
      txid: id("92"),
      vout: 1,
      amount_sats: S.p240,
      keychain: "external",
      confirmations: 4,
      locked: false,
      status: sending ? "sending" : "ready",
      actions: sending ? blockedActions({ kind: "sending" }) : PUBLIC_READY,
    },
  ];
}

/** Drains the picked coin, so the preview amount is that coin minus the fee. */
/** A small diagnostic ring that grows one line per poll, like a live wallet. */
const diagLines: string[] = [
  "sync: electrum sync starting",
  "sync: mweb download starting",
  "sync: mweb finished in 2140 ms",
];
function diagLogSince(args: Args) {
  const since = Number(args?.since ?? 0);
  diagLines.push(`cover: mempool checked, ${diagLines.length} txs seen`);
  const now = Math.floor(Date.now() / 1000);
  return {
    next: diagLines.length,
    lines: diagLines.slice(since).map((l) => `${now} ${l}`),
  };
}

function transferPreview(args: Args) {
  const req = (args?.req ?? {}) as {
    chain?: string;
    coin_id?: string;
    fee_rate_sat_vb?: number | null;
  };
  const isPublic = req.chain === "public";
  const coinSats = isPublic
    ? publicCoins().find((c) => c.outpoint === req.coin_id)?.amount_sats
    : privateCoins().find((c) => c.output_id === req.coin_id)?.amount_sats;
  const rate = req.fee_rate_sat_vb ?? 1;
  // One P2WPKH input to one P2WPKH output is about 110 vB.
  const feeSats = isPublic ? Math.ceil(110 * rate) : 2_000;
  return {
    to_account_index: 1,
    to_wallet_name: "Tip jar",
    address: isPublic ? PUBLIC_ADDRESS : PRIVATE_ADDRESS,
    amount_sats: (coinSats ?? S.p75) - feeSats,
    fee_sats: feeSats,
    fee_rate_sat_vb: isPublic ? rate : null,
    creates_change: false,
  };
}

const COMMANDS: Record<string, (args?: Args) => unknown> = {
  wallet_exists: () => scene() !== "recovery",
  wallet_needs_migration: () => false,
  wallet_is_locked: () => false,
  load_wallet: () => combined().transparent,
  list_wallets: () => [
    { index: 0, name: "Personal", is_active: true },
    { index: 1, name: "Tip jar", is_active: false },
  ],
  create_wallet_account: () => combined().transparent,
  switch_wallet: () => combined().transparent,
  warm_wallets: () => null,
  rename_wallet: () => [
    { index: 0, name: "Personal", is_active: true },
    { index: 1, name: "Tip jar", is_active: false },
  ],
  delete_wallet_account: () => combined().transparent,
  preview_transfer_coin: (args) => transferPreview(args),
  transfer_coin: (args) => {
    const preview = transferPreview(args);
    return {
      txid: id("xfer"),
      fee_sats: preview.fee_sats,
      address: preview.address,
      to_account_index: 1,
    };
  },
  get_summary: () => combined().transparent,
  get_combined_summary: () => combined(),
  get_tx_labels: () => ({}),
  list_transactions: () => transactions(),
  get_settings: () => settings(),
  fetch_spot_price: () => 84.2,
  fetch_fee_ladder: () => ({
    fastest_sat_vb: 3,
    half_hour_sat_vb: 2,
    hour_sat_vb: 1,
    economy_sat_vb: 1,
    minimum_sat_vb: 1,
  }),
  fetch_network_pulse: () => pulse(),
  diag_log_since: (args) => diagLogSince(args),
  fetch_insight_charts: () => charts(),
  sync_wallet: () => ({
    summary: combined().transparent,
    new_txs: 0,
    electrum_ms: 180,
    mweb_ms: 240,
    electrum_server: "electrum.example.com:50002",
    warnings: [],
  }),
  mweb_sync_progress: () => ({
    phase: "idle",
    active: false,
    fetched: 0,
    total: 0,
  }),
  get_diagnostics: () => ({
    app_version: "0.4.11",
    os: "macos",
    generated_unix: 1_700_000_000,
    network: "mainnet",
    electrum_url: "ssl://electrum.example.com:50002",
    electrum_validate_domain: true,
    electrum_use_public_fallback: true,
    active_electrum_url: "ssl://electrum.example.com:50002",
    mweb_scheme: "mwebd",
    mweb_peers: ["127.0.0.1:9333"],
    needs_full_scan: false,
    needs_mweb_scan: false,
    tip_height: 2_800_000,
    mweb_synced_height: 2_800_000,
    mweb_status: "MWEB synced",
    sync_phase: "idle",
    recent_log_lines: ["sync: done electrum_ms=100 mweb_ms=200 new_txs=0"],
  }),
  export_diagnostics: () => "/tmp/ldk-wallet-diagnostics.json",
  litvm_available: () => true,
  litvm_summary: () => litvmSummary(),
  get_litvm_settings: () => ({
    network: {
      id: "liteforge",
      display_name: "LiteForge",
      chain_id: 4441,
      rpc_http: "https://liteforge.example.com",
    },
    rpc_http: "https://liteforge.example.com",
    rpc_http_override: null,
    signing_enabled: true,
  }),
  litvm_history: () => litvmHistory(),
  list_unspent: () => publicCoins(),
  list_mweb_unspent: () => privateCoins(),
  preview_churn: (args) => ({
    input_sats: S.p75,
    hop_fee_sats: 50_000,
    resulting_sats: S.p75 - 50_000,
    target_depth: 1,
    total_fee_sats: 50_000,
    amount_note:
      "This subtracts the public fee. The resulting amount is still determined by where this coin started.",
    quiet_block_note:
      "A block that only contains this spend does not count, and this wallet will not try again by itself. Pressing Try again later signs a new hop and spends another 0.0005 LTC.",
    has_litecoin_rpc: new URLSearchParams(window.location.search).get("rpc") === "1",
    ...churnRequest(args),
  }),
  pump_churn_broadcast: () => null,
  default_electrum_urls: () => ["ssl://electrum.example.com:50002"],
};

export async function shotsInvoke<T>(cmd: string, args?: Args): Promise<T> {
  const build = COMMANDS[cmd];
  if (!build) throw new Error(`shots fixture missing command: ${cmd}`);
  return build(args) as T;
}
