// Property and boundary tests for UI amount parsing and formatting (HARDENING.md item 18).
import test from "node:test";
import assert from "node:assert/strict";
import {
  DUST_LITOSHIS,
  MAX_MONEY_SATS,
  formatAmountInputForUnit,
  formatLitoshis,
  formatLitoshisPlain,
  formatLtc,
  parseLitoshisToSats,
  parseLtcToSats,
  satsToBip21Amount,
} from "../ui/src/amounts.ts";

// Deterministic mulberry32 PRNG (same as scripts/phase-table.test.mjs).
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("parseLtcToSats enforces 8-decimal precision and MAX_MONEY_SATS ceiling", () => {
  assert.equal(parseLtcToSats("0"), 0);
  assert.equal(parseLtcToSats("0.00000001"), 1);
  assert.equal(parseLtcToSats(".0000294"), DUST_LITOSHIS);
  assert.equal(parseLtcToSats("1."), 100_000_000);
  assert.equal(parseLtcToSats("84000000"), MAX_MONEY_SATS);
  assert.equal(parseLtcToSats("84000000.00000000"), MAX_MONEY_SATS);

  // Above MAX_MONEY_SATS or unsafe integer range must be rejected (never lose precision).
  assert.equal(parseLtcToSats("84000000.00000001"), null);
  assert.equal(parseLtcToSats("84000001"), null);
  assert.equal(parseLtcToSats("9007199254740991"), null);
  assert.equal(parseLtcToSats("0.000000001"), null); // 9 decimals
  assert.equal(parseLtcToSats("-1"), null);
  assert.equal(parseLtcToSats("1,5"), null);
  assert.equal(parseLtcToSats("."), null);
  assert.equal(parseLtcToSats(""), null);
});

test("parseLitoshisToSats accepts valid thousands groups and rejects decimal-comma typos or overflow", () => {
  assert.equal(parseLitoshisToSats("0"), 0);
  assert.equal(parseLitoshisToSats("2940"), DUST_LITOSHIS);
  assert.equal(parseLitoshisToSats("2,940"), DUST_LITOSHIS);
  assert.equal(parseLitoshisToSats("1,000,000"), 1_000_000);
  assert.equal(parseLitoshisToSats(String(MAX_MONEY_SATS)), MAX_MONEY_SATS);
  assert.equal(parseLitoshisToSats("8,400,000,000,000,000"), MAX_MONEY_SATS);

  // Decimal-like comma typos and malformed comma placements must fail rather than silently multiplying by 10+.
  assert.equal(parseLitoshisToSats("1,5"), null);
  assert.equal(parseLitoshisToSats("0,01"), null);
  assert.equal(parseLitoshisToSats("12,34"), null);
  assert.equal(parseLitoshisToSats(",100"), null);
  assert.equal(parseLitoshisToSats("100,"), null);
  assert.equal(parseLitoshisToSats("0,100"), null);

  // Above MAX_MONEY_SATS or negative must fail.
  assert.equal(parseLitoshisToSats(String(MAX_MONEY_SATS + 1)), null);
  assert.equal(parseLitoshisToSats("-100"), null);
  assert.equal(parseLitoshisToSats("2940.5"), null);
});

test("seeded random round-trips hold for LTC, litoshis, and BIP21 formatting across [0, MAX_MONEY_SATS]", () => {
  for (let seed = 1; seed <= 250; seed++) {
    const rng = mulberry32(seed);
    const sats = Math.floor(rng() * (MAX_MONEY_SATS + 1));

    const ltcInput = formatAmountInputForUnit(sats, "ltc");
    assert.equal(parseLtcToSats(ltcInput), sats, `seed=${seed} ltcInput=${ltcInput}`);

    const litInput = formatAmountInputForUnit(sats, "litoshis");
    assert.equal(parseLitoshisToSats(litInput), sats, `seed=${seed} litInput=${litInput}`);

    const bip21 = satsToBip21Amount(sats);
    assert.equal(parseLtcToSats(bip21), sats, `seed=${seed} bip21=${bip21}`);

    const displayLtc = formatLtc(sats);
    assert.ok(displayLtc.endsWith(" LTC"));
    assert.equal(parseLtcToSats(displayLtc.slice(0, -4)), sats, `seed=${seed} displayLtc=${displayLtc}`);

    const grouped = formatLitoshisPlain(sats).replace(/ litoshis$/, "");
    assert.equal(parseLitoshisToSats(grouped), sats, `seed=${seed} grouped=${grouped}`);
    assert.equal(formatLitoshis(sats), `(${formatLitoshisPlain(sats)})`);
  }
});
