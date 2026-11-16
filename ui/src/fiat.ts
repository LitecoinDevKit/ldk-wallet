/** USD amount entry and display against an LTC/USD spot price. */

const SATS_PER_LTC = 100_000_000;

/** A last-known price older than this is not used to size a send. */
export const SEND_PRICE_MAX_AGE_MS = 5 * 60_000;

export function formatUsd(amount: number): string {
  return amount.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

export function isUsablePrice(price: number | null | undefined): price is number {
  return price != null && Number.isFinite(price) && price > 0;
}

/** Parse a USD decimal string (optional leading `$`). Rejects commas, negatives, >2 decimals. */
export function parseUsd(input: string): number | null {
  const raw = input.replace(/[\s\u00a0\u202f]+/g, "").replace(/^\$/, "");
  if (!raw || raw === "." || raw.includes(",") || raw.startsWith("-")) return null;
  if (!/^(\d+(\.\d*)?|\.\d+)$/.test(raw)) return null;
  const [wholePart = "", fracPart = ""] = raw.split(".");
  if (fracPart.length > 2) return null;
  const whole = wholePart ? Number(wholePart) : 0;
  if (!Number.isSafeInteger(whole)) return null;
  const cents = whole * 100 + Number(fracPart.padEnd(2, "0"));
  if (!Number.isSafeInteger(cents)) return null;
  return cents / 100;
}

export function usdToSats(usd: number, price: number): number | null {
  if (!isUsablePrice(price) || !Number.isFinite(usd) || usd < 0) return null;
  const sats = Math.round((usd / price) * SATS_PER_LTC);
  return Number.isSafeInteger(sats) ? sats : null;
}

export function parseUsdToSats(input: string, price: number): number | null {
  const usd = parseUsd(input);
  return usd == null ? null : usdToSats(usd, price);
}

export function satsToUsd(sats: number, price: number): number {
  return (sats / SATS_PER_LTC) * price;
}

/** "≈ $12.50 at $45.04/LTC" */
export function formatUsdAtPrice(sats: number, price: number): string {
  return `≈ ${formatUsd(satsToUsd(sats, price))} at ${formatUsd(price)}/LTC`;
}
