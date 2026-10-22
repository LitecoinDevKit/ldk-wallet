/**
 * Sample wallet for `?shots=1`. Addresses and amounts are documentation data.
 * Nothing here is read from a wallet on disk.
 *
 * Scenes (`?shots=1&scene=`):
 * - balance (default): two balances, a quiet sheet, status strip with an age
 * - coins: Private list with frozen, labeled, and maturing rows
 * - self-spend: that list, plus one row after a scored hop
 * - recovery: no wallet yet, so boot stays on create / restore
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
};

function quietCoin(partial: Coin): Coin {
  return {
    from_pegin: false,
    non_solo_blocks: 0,
    ...partial,
  };
}

function privateCoins(): Coin[] {
  const frozen = quietCoin({
    output_id: id("a1"),
    amount_sats: S.p120,
    confirmations: 40,
    mature: true,
    locked: true,
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
  };
  const current = scene();
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
    output_id: id("f6"),
    amount_sats: S.p75,
    confirmations: 30,
    mature: true,
  });
  if (current === "self-spend") return [scored, frozen, labeled, maturing];
  return [frozen, labeled, maturing, ordinary];
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
    litecoin_rpc_url: null,
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
    tip_height: TIP,
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

const COMMANDS: Record<string, () => unknown> = {
  wallet_exists: () => scene() !== "recovery",
  wallet_needs_migration: () => false,
  wallet_is_locked: () => false,
  load_wallet: () => combined().transparent,
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
    app_version: "0.4.9",
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
  list_unspent: () => [
    {
      outpoint: `${id("91")}:0`,
      txid: id("91"),
      vout: 0,
      amount_sats: S.p1000,
      keychain: "external",
      confirmations: 12,
      locked: false,
    },
    {
      outpoint: `${id("92")}:1`,
      txid: id("92"),
      vout: 1,
      amount_sats: S.p240,
      keychain: "external",
      confirmations: 4,
      locked: false,
    },
  ],
  list_mweb_unspent: () => privateCoins(),
  default_electrum_urls: () => ["ssl://electrum.example.com:50002"],
};

export async function shotsInvoke<T>(cmd: string): Promise<T> {
  const build = COMMANDS[cmd];
  if (!build) throw new Error(`shots fixture missing command: ${cmd}`);
  return build() as T;
}
