// Draws the UI lifecycle phases from PHASE_FROM in ui/src/phases.ts into
// docs/UI_PHASES.md. Exits non-zero when the doc is stale; --write refreshes it.
// Needs Node 22.18+ (loads the .ts file with built-in type stripping).
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PHASE_FROM } from "../ui/src/phases.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const doc = join(root, "docs/UI_PHASES.md");
const begin = "<!-- ui-phases:begin (generated; do not edit) -->\n";
const end = "<!-- ui-phases:end -->";

const lines = ["stateDiagram-v2", "    [*] --> boot"];
for (const [to, froms] of Object.entries(PHASE_FROM)) {
  for (const from of froms) lines.push(`    ${from} --> ${to}`);
}
const expected = "```mermaid\n" + lines.join("\n") + "\n```\n";

const text = readFileSync(doc, "utf8").replace(/\r\n/g, "\n");
const start = text.indexOf(begin);
const stop = text.indexOf(end);
if (start < 0 || stop < 0) {
  console.error(`docs/UI_PHASES.md is missing the ui-phases markers`);
  process.exit(1);
}
const current = text.slice(start + begin.length, stop);

if (process.argv.includes("--write")) {
  writeFileSync(doc, text.slice(0, start + begin.length) + expected + text.slice(stop));
} else if (current !== expected) {
  console.error("docs/UI_PHASES.md is stale. Run npm run check:diagrams -- --write");
  process.exit(1);
}
