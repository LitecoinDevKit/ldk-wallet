// Pure LTC / litoshi amount parsing, formatting, and consensus money bounds (HARDENING.md item 18).
// Kept free of DOM and IPC dependencies so `scripts/amounts.test.mjs` can exercise it directly.

/** Maximum Litecoin supply in litoshis (84,000,000 LTC = 8,400,000,000,000,000 litoshis < Number.MAX_SAFE_INTEGER). */
export const MAX_MONEY_SATS = 8_400_000_000_000_000;

/** Litecoin Core P2WPKH dust floor at 30 sat/vB (`DUST_RELAY_TX_FEE = 30,000`). */
export const DUST_LITOSHIS = 2940;

export type DisplayUnit = "ltc" | "litoshis";

export function formatLtc(sats: number): string {
  const whole = Math.trunc(sats / 100_000_000);
  const frac = Math.abs(sats % 100_000_000)
    .toString()
    .padStart(8, "0");
  const sign = sats < 0 ? "-" : "";
  return `${sign}${whole}.${frac} LTC`;
}

export function formatLitoshisPlain(sats: number): string {
  return `${sats.toLocaleString("en-US")} litoshis`;
}

export function formatLitoshis(sats: number): string {
  return `(${formatLitoshisPlain(sats)})`;
}

/**
 * Parse an LTC decimal string to integer litoshis.
 * Rejects commas, negatives, >8 decimals, and values above `MAX_MONEY_SATS`.
 */
export function parseLtcToSats(input: string): number | null {
  // Strip all whitespace (incl. non-breaking/narrow spaces from pasted text).
  const raw = input.replace(/[\s\u00a0\u202f]+/g, "");
  if (!raw || raw === "." || raw.includes(",") || raw.startsWith("-")) return null;
  // Allow ".009" and "5." in addition to "0.009".
  if (!/^(\d+(\.\d*)?|\.\d+)$/.test(raw)) return null;
  const [wholePart = "", fracPart = ""] = raw.split(".");
  if (fracPart.length > 8) return null;
  const whole = wholePart ? Number(wholePart) : 0;
  if (!Number.isSafeInteger(whole) || whole < 0 || whole > 84_000_000) return null;
  const frac = Number(fracPart.padEnd(8, "0"));
  if (!Number.isSafeInteger(frac) || frac < 0) return null;
  const total = whole * 100_000_000 + frac;
  if (!Number.isSafeInteger(total) || total < 0 || total > MAX_MONEY_SATS) return null;
  return total;
}

/**
 * Parse integer litoshis (no decimals).
 * Accepts either plain digits (`2940`) or valid US thousands-grouped digits (`2,940`, `1,000,000`),
 * while rejecting decimal-like comma typos (`1,5` or `0,01`) and values above `MAX_MONEY_SATS`.
 */
export function parseLitoshisToSats(input: string): number | null {
  const raw = input.replace(/[\s\u00a0\u202f]+/g, "");
  if (!raw || raw.startsWith("-")) return null;
  if (raw.includes(",")) {
    if (!/^[1-9]\d{0,2}(,\d{3})+$/.test(raw)) return null;
  } else if (!/^\d+$/.test(raw)) {
    return null;
  }
  const normalized = raw.replace(/,/g, "");
  const n = Number(normalized);
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_MONEY_SATS) return null;
  return n;
}

/** Format sats into the given unit for amount input fields. */
export function formatAmountInputForUnit(sats: number, unit: DisplayUnit): string {
  if (unit === "litoshis") return String(sats);
  const whole = Math.trunc(sats / 100_000_000);
  const frac = Math.abs(sats % 100_000_000)
    .toString()
    .padStart(8, "0")
    .replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : String(whole);
}

/** BIP21 amount is always LTC decimal (not litoshis). */
export function satsToBip21Amount(sats: number): string {
  return formatAmountInputForUnit(sats, "ltc");
}
