import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(root, "ui", "screenshots");
const base = "http://127.0.0.1:1420";

function startVite() {
  const child = spawn("npm", ["run", "dev", "--", "--host", "127.0.0.1"], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (chunk) => {
    log += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    log += chunk.toString();
  });
  return { child, readLog: () => log };
}

async function waitForServer(readLog) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(base);
      if (response.ok) return;
    } catch {
      /* vite still binding the port */
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Vite did not start on ${base}\n${readLog()}`);
}

async function prepare(page, scene) {
  const query = scene === "balance" ? "shots=1" : `shots=1&scene=${scene}`;
  await page.goto(`${base}/?${query}`);
  await page.locator("#ready").waitFor({ state: "visible" });
  await page.locator("#loading-overlay").waitFor({ state: "hidden" });
  await page.locator("#status-block", { hasText: "1 minute ago" }).waitFor();
  await page.locator("#toast").waitFor({ state: "visible", timeout: 15_000 });
  await page.locator("#toast").waitFor({ state: "hidden" });
  if (scene === "balance") {
    for (const id of ["#backup-banner", "#maturity-banner", "#churn-banner", "#churn-job-banner", "#modal-overlay"]) {
      if (await page.locator(id).isVisible()) {
        throw new Error(`${id} is visible on the balance scene`);
      }
    }
  }
}

async function main() {
  await mkdir(outDir, { recursive: true });
  const vite = startVite();
  const browser = await chromium.launch();
  try {
    await waitForServer(vite.readLog);
    const page = await browser.newPage({
      viewport: { width: 1000, height: 760 },
      deviceScaleFactor: 2,
      colorScheme: "dark",
    });
    await page.addInitScript(() => {
      localStorage.setItem("ltc-theme", "dark");
      localStorage.setItem("ltc-backup-verified", "1");
      localStorage.setItem("ltc-backup-banner-dismissed", "1");
      localStorage.setItem("ltc-mweb-coach-seen", "1");
      localStorage.setItem("ltc-security-checklist-dismissed", "1");
      localStorage.setItem("ltc-first-receive-seen", "1");
    });

    await prepare(page, "balance");
    await page.locator("#balance-mweb").waitFor({ state: "visible" });
    await page.screenshot({ path: path.join(outDir, "balance.png") });

    await page.locator("#nav-insights").click();
    await page.locator(".chart-card").first().waitFor();
    await page.locator(".content").screenshot({ path: path.join(outDir, "insights.png") });

    await page.locator("#nav-litvm").click();
    await page.getByText("LiteForge testnet.").waitFor();
    await page.locator(".content").screenshot({ path: path.join(outDir, "litvm.png") });

    await prepare(page, "coins");
    await page.locator("#nav-coins").click();
    await page.locator("#coins-seg-private").click();
    await page.getByText("maturing · 4 blocks left").waitFor();
    await page.waitForFunction(() =>
      [...document.querySelectorAll("#coins-mweb-list input")].some(
        (input) => input instanceof HTMLInputElement && input.value === "Savings",
      ),
    );
    await page.locator("#coins-mweb-list").getByText("frozen").waitFor();
    await page.locator(".content").screenshot({ path: path.join(outDir, "coins.png") });

    await page.locator("#nav-send").click();
    await page.locator("#send-seg-private").click();
    await page.locator("#mweb-send-coin-control summary").click();
    const savings = page.locator("#mweb-send-utxo-list li").filter({ hasText: "Savings" });
    await savings.locator('input[type="checkbox"]').check();
    await page.locator("#mweb-send-coin-control").evaluate((el) => {
      el.scrollIntoView({ block: "start" });
    });
    await page.locator(".content").screenshot({ path: path.join(outDir, "send-private.png") });

    await prepare(page, "self-spend");
    await page.locator("#nav-coins").click();
    await page.locator("#coins-seg-private").click();
    await page.getByText("This block also had 4 other kernels and 7 other outputs.").waitFor();
    await page.locator(".content").screenshot({ path: path.join(outDir, "self-spend.png") });
  } finally {
    await browser.close();
    vite.child.kill("SIGTERM");
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
