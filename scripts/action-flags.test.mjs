// Consistency and static source checks for UI action flags (HARDENING.md item 6).
// Loaded with Node's built-in TypeScript stripping (same as scripts/phase-table.test.mjs).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  churnActionButtons,
  churnPhaseActive,
  coinBlockedTitle,
  freezeLabel,
  freezeTargetLocked,
  privateCoinActionState,
  publicCoinActionState,
} from "../ui/src/actions.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const mainTsPath = join(root, "ui/src/main.ts");
const shotsFixturePath = join(root, "ui/src/shots-fixture.ts");

const COIN_STATUSES = [
  "churning",
  "sending",
  "pending",
  "maturing",
  "frozen",
  "tied-to-pegin",
  "ready",
];

const CHURN_PHASES = [
  "waiting-to-broadcast",
  "waiting-for-cover",
  "waiting-confirm",
  "paused-solo",
  "paused-unscored",
  "done",
  "cancelled",
];

const BLOCK_SAMPLES = [
  null,
  { kind: "churning" },
  { kind: "sending" },
  { kind: "frozen" },
  { kind: "unconfirmed" },
  { kind: "maturing", blocks_left: 1 },
  { kind: "maturing", blocks_left: 4 },
];

test("churnPhaseActive matches the five active backend phases", () => {
  const active = CHURN_PHASES.filter((p) => churnPhaseActive(p));
  assert.deepEqual(active, [
    "waiting-to-broadcast",
    "waiting-for-cover",
    "waiting-confirm",
    "paused-solo",
    "paused-unscored",
  ]);
  assert.equal(churnPhaseActive(null), false);
  assert.equal(churnPhaseActive(undefined), false);
});

test("churnActionButtons maps every ChurnActions flag combination to the expected buttons", () => {
  assert.deepEqual(churnActionButtons(null, null), []);
  assert.deepEqual(churnActionButtons(undefined, "retry"), []);

  for (const retry of [false, true]) {
    for (const open_settings of [false, true]) {
      for (const cancel of [false, true]) {
        for (const pending of [null, "retry", "cancel"]) {
          const buttons = churnActionButtons({ retry, cancel, open_settings }, pending);
          const ids = buttons.map((b) => b.id);
          const expectedIds = [
            ...(retry ? ["retry"] : []),
            ...(open_settings ? ["open-settings"] : []),
            ...(cancel ? ["cancel"] : []),
          ];
          assert.deepEqual(ids, expectedIds);

          for (const btn of buttons) {
            assert.equal(btn.disabled, pending != null);
            if (btn.id === "retry") {
              assert.equal(btn.label, "Try again");
              assert.equal(btn.kind, "primary");
            } else if (btn.id === "open-settings") {
              assert.equal(btn.label, "Open Settings");
              assert.equal(btn.kind, "primary");
            } else if (btn.id === "cancel") {
              assert.equal(btn.label, "Cancel");
              assert.equal(btn.kind, "ghost");
            }
          }
        }
      }
    }
  }
});

test("freezeTargetLocked and freezeLabel derive freeze requests from actions alone", () => {
  assert.equal(freezeTargetLocked({ freeze: true, unfreeze: false }), true);
  assert.equal(freezeLabel({ unfreeze: false }), "Freeze");

  assert.equal(freezeTargetLocked({ freeze: false, unfreeze: true }), false);
  assert.equal(freezeLabel({ unfreeze: true }), "Unfreeze");

  assert.equal(freezeTargetLocked({ freeze: false, unfreeze: false }), null);
  assert.equal(freezeTargetLocked({ freeze: true, unfreeze: true }), null);
});

test("privateCoinActionState and publicCoinActionState obey every CoinActions flag combination", () => {
  for (const status of COIN_STATUSES) {
    for (const blocked of BLOCK_SAMPLES) {
      for (let mask = 0; mask < 64; mask++) {
        const actions = {
          spend_to_self: Boolean(mask & 1),
          split: Boolean(mask & 2),
          transfer: Boolean(mask & 4),
          select: Boolean(mask & 8),
          freeze: Boolean(mask & 16),
          unfreeze: Boolean(mask & 32),
          blocked,
        };
        for (const hasOtherWallets of [false, true]) {
          for (const inFlightSpend of [false, true]) {
            const priv = privateCoinActionState(
              { status, actions },
              { hasOtherWallets, inFlightSpend },
            );
            const expectedPrivHold =
              status === "churning" || status === "sending" || inFlightSpend;
            assert.equal(priv.jobHolds, expectedPrivHold);
            assert.equal(
              priv.spendToSelf.visible,
              !expectedPrivHold && actions.spend_to_self,
            );
            assert.equal(
              priv.spendToSelf.kind,
              status === "tied-to-pegin" ? "primary" : "ghost",
            );

            const expectedTarget =
              actions.freeze && !actions.unfreeze
                ? true
                : actions.unfreeze && !actions.freeze
                  ? false
                  : null;
            assert.equal(priv.freeze.targetLocked, expectedTarget);
            assert.equal(priv.freeze.disabled, expectedTarget == null);
            assert.equal(priv.freeze.label, actions.unfreeze ? "Unfreeze" : "Freeze");
            assert.equal(
              priv.freeze.title,
              expectedTarget == null ? coinBlockedTitle(blocked, "spend", "private") : "",
            );

            assert.equal(priv.split.disabled, !actions.split);
            assert.equal(
              priv.split.title,
              actions.split
                ? "Split this private coin into multiple outputs"
                : coinBlockedTitle(blocked, "split", "private"),
            );

            assert.equal(priv.transfer.disabled, !(actions.transfer && hasOtherWallets));
            assert.equal(
              priv.transfer.title,
              !actions.transfer
                ? coinBlockedTitle(blocked, "transfer", "private")
                : !hasOtherWallets
                  ? "Add another wallet to transfer coins between them."
                  : "Send this coin to another wallet on this device",
            );

            assert.equal(priv.select.disabled, !actions.select);
            assert.equal(
              priv.select.title,
              actions.select
                ? "Include this coin"
                : coinBlockedTitle(blocked, "spend", "private"),
            );

            const pub = publicCoinActionState(
              { status, actions },
              { hasOtherWallets, inFlightSpend },
            );
            assert.equal(pub.jobHolds, inFlightSpend);
            assert.equal(pub.spendToSelf.visible, false);
            assert.equal(pub.freeze.targetLocked, expectedTarget);
            assert.equal(pub.freeze.disabled, expectedTarget == null);
            assert.equal(pub.freeze.label, actions.unfreeze ? "Unfreeze" : "Freeze");
            assert.equal(
              pub.freeze.title,
              expectedTarget == null ? coinBlockedTitle(blocked, "spend", "public") : "",
            );
            assert.equal(pub.split.disabled, !actions.split);
            assert.equal(
              pub.split.title,
              actions.split
                ? "Split this coin into multiple outputs"
                : coinBlockedTitle(blocked, "split", "public"),
            );
            assert.equal(pub.transfer.disabled, !(actions.transfer && hasOtherWallets));
            assert.equal(
              pub.transfer.title,
              !actions.transfer
                ? coinBlockedTitle(blocked, "transfer", "public")
                : !hasOtherWallets
                  ? "Add another wallet to transfer coins between them."
                  : "Send this coin to another wallet on this device",
            );
            assert.equal(pub.select.disabled, !actions.select);
            assert.equal(
              pub.select.title,
              actions.select
                ? "Include this coin"
                : coinBlockedTitle(blocked, "spend", "public"),
            );
          }
        }
      }
    }
  }
});

test("canonical backend coin_status and public_coin_status profiles map to the right UI controls", () => {
  const readyActions = {
    spend_to_self: true,
    split: true,
    transfer: true,
    select: true,
    freeze: true,
    unfreeze: false,
    blocked: null,
  };
  const readyPriv = privateCoinActionState(
    { status: "ready", actions: readyActions },
    { hasOtherWallets: true },
  );
  assert.equal(readyPriv.jobHolds, false);
  assert.equal(readyPriv.spendToSelf.visible, true);
  assert.equal(readyPriv.spendToSelf.kind, "ghost");
  assert.equal(readyPriv.freeze.disabled, false);
  assert.equal(readyPriv.freeze.label, "Freeze");
  assert.equal(readyPriv.freeze.targetLocked, true);
  assert.equal(readyPriv.split.disabled, false);
  assert.equal(readyPriv.transfer.disabled, false);
  assert.equal(readyPriv.select.disabled, false);

  const tiedPriv = privateCoinActionState(
    { status: "tied-to-pegin", actions: readyActions },
    { hasOtherWallets: true },
  );
  assert.equal(tiedPriv.spendToSelf.visible, true);
  assert.equal(tiedPriv.spendToSelf.kind, "primary");

  const frozenActions = {
    spend_to_self: false,
    split: false,
    transfer: false,
    select: false,
    freeze: false,
    unfreeze: true,
    blocked: { kind: "frozen" },
  };
  const frozenPriv = privateCoinActionState(
    { status: "frozen", actions: frozenActions },
    { hasOtherWallets: true },
  );
  assert.equal(frozenPriv.spendToSelf.visible, false);
  assert.equal(frozenPriv.freeze.disabled, false);
  assert.equal(frozenPriv.freeze.label, "Unfreeze");
  assert.equal(frozenPriv.freeze.targetLocked, false);
  assert.equal(frozenPriv.split.disabled, true);
  assert.equal(frozenPriv.split.title, "Unfreeze to split.");
  assert.equal(frozenPriv.transfer.disabled, true);
  assert.equal(frozenPriv.transfer.title, "Unfreeze to transfer.");
  assert.equal(frozenPriv.select.disabled, true);
  assert.equal(frozenPriv.select.title, "Unfreeze to spend.");

  const maturingActions = {
    spend_to_self: false,
    split: false,
    transfer: false,
    select: false,
    freeze: false,
    unfreeze: false,
    blocked: { kind: "maturing", blocks_left: 4 },
  };
  const maturingPriv = privateCoinActionState(
    { status: "maturing", actions: maturingActions },
    { hasOtherWallets: true },
  );
  assert.equal(maturingPriv.jobHolds, false);
  assert.equal(maturingPriv.spendToSelf.visible, false);
  assert.equal(maturingPriv.freeze.disabled, true);
  assert.equal(maturingPriv.freeze.title, "Matures in 4 blocks.");
  assert.equal(maturingPriv.split.disabled, true);
  assert.equal(maturingPriv.split.title, "Matures in 4 blocks.");

  const maturingPub = publicCoinActionState(
    { status: "maturing", actions: maturingActions },
    { hasOtherWallets: true },
  );
  assert.equal(maturingPub.jobHolds, false);
  assert.equal(maturingPub.spendToSelf.visible, false);
  assert.equal(maturingPub.select.disabled, true);
  assert.equal(maturingPub.select.title, "Matures in 4 blocks.");
  assert.equal(maturingPub.freeze.disabled, true);
  assert.equal(maturingPub.freeze.targetLocked, null);
  assert.equal(maturingPub.freeze.title, "Matures in 4 blocks.");
  assert.equal(maturingPub.split.disabled, true);
  assert.equal(maturingPub.split.title, "Matures in 4 blocks.");
  assert.equal(maturingPub.transfer.disabled, true);
  assert.equal(maturingPub.transfer.title, "Matures in 4 blocks.");

  const pendingPublicActions = {
    spend_to_self: false,
    split: false,
    transfer: false,
    select: true,
    freeze: true,
    unfreeze: false,
    blocked: { kind: "unconfirmed" },
  };
  const pendingPub = publicCoinActionState(
    { status: "pending", actions: pendingPublicActions },
    { hasOtherWallets: true },
  );
  assert.equal(pendingPub.select.disabled, false);
  assert.equal(pendingPub.freeze.disabled, false);
  assert.equal(pendingPub.freeze.targetLocked, true);
  assert.equal(pendingPub.split.disabled, true);
  assert.equal(pendingPub.split.title, "Split is disabled until the coin is confirmed.");
  assert.equal(pendingPub.transfer.disabled, true);
  assert.equal(pendingPub.transfer.title, "Transfer is disabled until the coin is confirmed.");
});

/**
 * Slice a top-level function body from `ui/src/main.ts` by name so static checks
 * can inspect which functions touch phases or coin fields.
 */
function extractFunctionSlices(source) {
  const declRe = /^(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(/gm;
  const starts = [];
  let match;
  while ((match = declRe.exec(source)) !== null) {
    starts.push({ name: match[1], index: match.index });
  }
  const slices = new Map();
  for (let i = 0; i < starts.length; i++) {
    const start = starts[i].index;
    const end = i + 1 < starts.length ? starts[i + 1].index : source.length;
    slices.set(starts[i].name, source.slice(start, end));
  }
  return slices;
}

test("static check: ui/src/main.ts never reads .locked or .mature on coins and only reads coin .confirmations for conf labels", () => {
  const source = readFileSync(mainTsPath, "utf8");

  const lockedReads = [...source.matchAll(/\b(?:coin|utxo|row|c|u)\??\.locked\b/g)];
  assert.deepEqual(
    lockedReads.map((m) => m[0]),
    [],
    "ui/src/main.ts must not read or write .locked on coins; use actions.freeze / actions.unfreeze",
  );

  const matureReads = [...source.matchAll(/\b(?:coin|utxo|row|c|u)\??\.mature\b/g)];
  assert.deepEqual(
    matureReads.map((m) => m[0]),
    [],
    "ui/src/main.ts must not read .mature on coins; use coin.status and coin.actions",
  );

  const slices = extractFunctionSlices(source);
  const allowedCoinConfFunctions = new Set([
    "publicConfLabel",
    "renderMwebCoinsList",
    "renderMwebControlList",
  ]);
  for (const [fnName, body] of slices.entries()) {
    if (/\b(?:coin|utxo)\??\.confirmations\b/.test(body)) {
      assert.ok(
        allowedCoinConfFunctions.has(fnName),
        `unexpected coin .confirmations read in function ${fnName}`,
      );
      assert.ok(
        !/\.disabled\s*=.*confirmations/.test(body),
        `function ${fnName} must not gate button .disabled on .confirmations`,
      );
    }
  }
});

test("static check: ui/src/main.ts never infers a churn or coin action from churn_phase", () => {
  const source = readFileSync(mainTsPath, "utf8");
  const slices = extractFunctionSlices(source);

  // Functions allowed to read churn_phase / churnPhaseActive for status copy,
  // pills, sort order, banners, or card tone — never for action buttons.
  const allowedChurnPhaseFunctions = new Set([
    "stampChurnStarting",
    "churnCoverLine",
    "activeChurnCoin",
    "churnCompanySentence",
    "churnRowMain",
    "churnVisibleError",
    "churnPill",
    "churnSmallerLine",
    "churnNeedsAttention",
    "churnJobNotice",
    "churnSummaryToken",
    "renderChurnStatus",
  ]);

  for (const [fnName, body] of slices.entries()) {
    if (/\b(?:churn_phase|churnPhaseActive)\b/.test(body)) {
      assert.ok(
        allowedChurnPhaseFunctions.has(fnName),
        `function ${fnName} references churn_phase or churnPhaseActive outside the allowlist`,
      );
    }
  }

  // Inside renderChurnStatus, churn_phase may only appear before the actions block (for card tone),
  // and the actions block must delegate to churnActionButtons(coin.churn_actions, churnPending).
  const renderChurnBody = slices.get("renderChurnStatus") ?? "";
  const actionsMarker = 'actions.className = "churn-status-actions"';
  const actionsStart = renderChurnBody.indexOf(actionsMarker);
  assert.ok(actionsStart > 0, "renderChurnStatus is missing .churn-status-actions");
  const actionsSection = renderChurnBody.slice(actionsStart);
  assert.ok(
    !/\b(?:churn_phase|churnPhaseActive)\b/.test(actionsSection),
    "renderChurnStatus must not check churn_phase inside the .churn-status-actions section",
  );
  assert.ok(
    actionsSection.includes("churnActionButtons(coin.churn_actions, churnPending)"),
    "renderChurnStatus must build buttons from churnActionButtons(coin.churn_actions, churnPending)",
  );

  // Coin lists, pickers, and freeze toggles must delegate to ui/src/actions.ts helpers.
  assert.ok(
    (slices.get("renderUtxoList") ?? "").includes("publicCoinActionState(utxo)"),
    "renderUtxoList must use publicCoinActionState",
  );
  assert.ok(
    (slices.get("renderUtxoList") ?? "").includes(
      "if (actionState.select.disabled) panel.selected.delete(utxo.outpoint)",
    ),
    "renderUtxoList must prune unselectable coins from panel.selected",
  );
  assert.ok(
    (slices.get("renderMwebControlList") ?? "").includes("privateCoinActionState(coin)"),
    "renderMwebControlList must use privateCoinActionState",
  );
  assert.ok(
    (slices.get("renderMwebControlList") ?? "").includes(
      "if (actionState.select.disabled) panel.selected.delete(coin.output_id)",
    ),
    "renderMwebControlList must prune unselectable coins from panel.selected",
  );
  assert.ok(
    (slices.get("renderCoinsList") ?? "").includes("publicCoinActionState(utxo"),
    "renderCoinsList must use publicCoinActionState",
  );
  assert.ok(
    (slices.get("renderMwebCoinsList") ?? "").includes("privateCoinActionState(coin"),
    "renderMwebCoinsList must use privateCoinActionState",
  );
  assert.ok(
    (slices.get("toggleUtxoLocked") ?? "").includes("freezeTargetLocked(utxo.actions)"),
    "toggleUtxoLocked must use freezeTargetLocked(utxo.actions)",
  );
  assert.ok(
    (slices.get("toggleMwebLocked") ?? "").includes("freezeTargetLocked(coin.actions)"),
    "toggleMwebLocked must use freezeTargetLocked(coin.actions)",
  );
});

test("static check: LitVM Speed up is the only remaining UI-inferred action button, and shots-fixture uses only active churn_phase values", () => {
  const source = readFileSync(mainTsPath, "utf8");
  const slices = extractFunctionSlices(source);

  const speedUpMatches = [
    ...source.matchAll(/tx\.pending\s*&&\s*!tx\.failed\s*&&\s*!tx\.incoming/g),
  ];
  assert.equal(
    speedUpMatches.length,
    1,
    "expected exactly one LitVM Speed up predicate (documented in AGENTS.md)",
  );
  assert.ok(
    (slices.get("renderLitvmHistory") ?? "").includes(
      "tx.pending && !tx.failed && !tx.incoming",
    ),
    "LitVM Speed up predicate must live in renderLitvmHistory",
  );

  const fixtureSource = readFileSync(shotsFixturePath, "utf8");
  const fixturePhaseLiterals = [
    ...fixtureSource.matchAll(/churn_phase\s*[:=]\s*"([^"]+)"/g),
  ].map((m) => m[1]);
  assert.ok(fixturePhaseLiterals.length > 0);
  for (const phase of fixturePhaseLiterals) {
    assert.ok(
      churnPhaseActive(phase),
      `shots-fixture sets non-active churn_phase "${phase}" on a coin row`,
    );
  }
});
