// Kept free of DOM and imports: `scripts/phase-diagram.mjs` loads this file in
// Node to draw docs/UI_PHASES.md.

export type Phase =
  | "boot"
  | "onboarding"
  | "mnemonic"
  | "ready"
  | "fatal"
  | "unlock"
  | "migrate";

export const PHASE_LABELS: Record<Phase, string> = {
  boot: "Starting…",
  onboarding: "Set up your wallet",
  mnemonic: "Back up your phrase",
  ready: "Ready",
  fatal: "Wallet data problem",
  unlock: "Locked",
  migrate: "Encryption required",
};

const ALL_PHASES: readonly Phase[] = Object.keys(PHASE_LABELS) as Phase[];

/** Phases each phase may be entered from. `fatal` is reachable from anywhere. */
export const PHASE_FROM: Record<Phase, readonly Phase[]> = {
  boot: ["boot"],
  onboarding: ["boot", "fatal", "unlock"],
  mnemonic: ["onboarding"],
  migrate: ["boot"],
  unlock: ["boot", "ready"],
  ready: ["boot", "unlock", "migrate", "onboarding", "mnemonic", "ready"],
  fatal: ALL_PHASES,
};
