// Property and graph-invariant tests for the UI phase table in ui/src/phases.ts.
// Loaded with Node's built-in TypeScript stripping (same as scripts/phase-diagram.mjs).
import test from "node:test";
import assert from "node:assert/strict";
import { PHASE_FROM, PHASE_LABELS, canEnter } from "../ui/src/phases.ts";

const PHASES = Object.keys(PHASE_LABELS);

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("PHASE_FROM and PHASE_LABELS define the same phase set with no duplicates", () => {
  assert.deepEqual(Object.keys(PHASE_FROM).sort(), [...PHASES].sort());
  for (const [to, froms] of Object.entries(PHASE_FROM)) {
    const unique = new Set(froms);
    assert.equal(unique.size, froms.length, `duplicate source phase for ${to}`);
    for (const from of froms) {
      assert.ok(PHASES.includes(from), `unknown source phase ${from} for ${to}`);
    }
  }
});

test("canEnter matches PHASE_FROM and self-loops match documented phases", () => {
  const selfLoops = [];
  for (const from of PHASES) {
    for (const to of PHASES) {
      const expected = PHASE_FROM[to].includes(from);
      assert.equal(
        canEnter(from, to),
        expected,
        `canEnter(${from}, ${to}) disagreed with PHASE_FROM`,
      );
    }
    if (canEnter(from, from)) selfLoops.push(from);
  }
  assert.deepEqual(selfLoops.sort(), ["boot", "fatal", "ready"]);
});

test("every phase (including ready) is reachable from boot", () => {
  const visited = new Set(["boot"]);
  const queue = ["boot"];
  while (queue.length > 0) {
    const from = queue.shift();
    for (const to of PHASES) {
      if (canEnter(from, to) && !visited.has(to)) {
        visited.add(to);
        queue.push(to);
      }
    }
  }
  assert.ok(visited.has("ready"), "ready is not reachable from boot");
  for (const phase of PHASES) {
    assert.ok(visited.has(phase), `${phase} is not reachable from boot`);
  }
});

test("fatal is reachable from every phase and its only non-self exit is onboarding", () => {
  for (const from of PHASES) {
    assert.equal(canEnter(from, "fatal"), true, `cannot enter fatal from ${from}`);
  }
  const nonSelfExits = PHASES.filter((to) => to !== "fatal" && canEnter("fatal", to));
  assert.deepEqual(nonSelfExits, ["onboarding"]);
});

/**
 * Run one deterministic random walk starting from `boot`.
 * Replay a single failing seed by calling `walkUi(seed)`.
 */
function walkUi(seed, stepsPerWalk = 30) {
  const nextRand = mulberry32(seed);
  let current = "boot";
  const steps = [];
  const visited = new Set([current]);
  let accepted = 0;
  let rejected = 0;

  for (let step = 0; step < stepsPerWalk; step++) {
    const target = PHASES[Math.floor(nextRand() * PHASES.length)];
    const from = current;
    const allowed = canEnter(from, target);

    // Mirrors setPhase in ui/src/main.ts: ignore disallowed targets.
    if (allowed) {
      current = target;
      accepted++;
    } else {
      rejected++;
    }
    steps.push(`#${step}: ${from} -> ${target} (${allowed ? "ok" : "rejected"}) => ${current}`);

    if (allowed) {
      assert.equal(
        current,
        target,
        `seed=${seed} accepted move did not reach target\n${steps.join("\n")}`,
      );
      assert.ok(
        PHASE_FROM[target].includes(from),
        `seed=${seed} accepted move not in PHASE_FROM\n${steps.join("\n")}`,
      );
    } else {
      assert.equal(
        current,
        from,
        `seed=${seed} rejected move changed current phase\n${steps.join("\n")}`,
      );
      assert.ok(
        !PHASE_FROM[target].includes(from),
        `seed=${seed} rejected move was in PHASE_FROM\n${steps.join("\n")}`,
      );
    }

    visited.add(current);
  }

  return { visited, accepted, rejected };
}

test("500 seeded random walks of 30 steps obey PHASE_FROM and visit every phase", () => {
  const SEEDS = 500;
  const STEPS = 30;
  const allVisited = new Set();
  let totalAccepted = 0;
  let totalRejected = 0;

  for (let seed = 0; seed < SEEDS; seed++) {
    const res = walkUi(seed, STEPS);
    for (const p of res.visited) allVisited.add(p);
    totalAccepted += res.accepted;
    totalRejected += res.rejected;
  }

  for (const phase of PHASES) {
    assert.ok(allVisited.has(phase), `phase ${phase} was never visited across ${SEEDS}x${STEPS} walks`);
  }
  assert.ok(totalAccepted > 0, "walks never accepted a transition");
  assert.ok(totalRejected > 0, "walks never rejected a transition");
});
