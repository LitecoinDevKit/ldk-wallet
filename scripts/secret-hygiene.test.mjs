// Static UI secret-hygiene checks (HARDENING.md item 16).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const mainTs = readFileSync(join(root, "ui/src/main.ts"), "utf8");

function extractFunctionBody(src, header) {
  const start = src.indexOf(header);
  assert.notEqual(start, -1, `missing ${header} in ui/src/main.ts`);
  const open = src.indexOf("{", start);
  assert.notEqual(open, -1, `missing opening brace for ${header}`);
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    if (src[i] === "{") depth += 1;
    else if (src[i] === "}") {
      depth -= 1;
      if (depth === 0) return src.slice(open, i + 1);
    }
  }
  assert.fail(`unterminated ${header}`);
}

test("clearSecretInputs wipes pending mnemonic and all passphrase/seed DOM fields", () => {
  const body = extractFunctionBody(mainTs, "function clearSecretInputs()");
  for (const needle of [
    "clearPendingMnemonic()",
    'el.restoreMnemonic.value = ""',
    'el.restoreAezeedPass.value = ""',
    'el.restorePassphrase.value = ""',
    'el.restorePassphrase2.value = ""',
    'el.onboardPassphrase.value = ""',
    'el.onboardPassphrase2.value = ""',
    'el.migratePassphrase.value = ""',
    'el.migratePassphrase2.value = ""',
    'el.unlockPassphrase.value = ""',
    'el.settingsRpc.value = ""',
  ]) {
    assert.ok(body.includes(needle), `clearSecretInputs must execute ${needle}`);
  }
});

test("lockWallet and wipeAndOnboard both invoke clearSecretInputs", () => {
  const lockBody = extractFunctionBody(mainTs, "async function lockWallet(");
  assert.ok(
    lockBody.includes("clearSecretInputs()"),
    "lockWallet (manual lock and inactivity auto-lock) must clear secret inputs",
  );
  assert.ok(
    lockBody.includes('await invoke("lock_wallet")'),
    "lockWallet must invoke backend lock_wallet",
  );

  const wipeBody = extractFunctionBody(mainTs, "async function wipeAndOnboard()");
  assert.ok(
    wipeBody.includes("clearSecretInputs()"),
    "wipeAndOnboard must clear secret inputs",
  );
});
