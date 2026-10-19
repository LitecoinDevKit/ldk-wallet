# macOS signing and notarization

CI is already wired for Apple Developer ID signing + notarization. Without
repository secrets, macOS release artifacts stay **unsigned** (Linux is
unaffected).

## Required GitHub repository secrets

| Secret | Purpose |
| --- | --- |
| `APPLE_CERTIFICATE` | Base64-encoded `.p12` Developer ID Application certificate |
| `APPLE_CERTIFICATE_PASSWORD` | Password for that `.p12` |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_ID` | Apple ID email used for notarization |
| `APPLE_PASSWORD` | App-specific password (not the account password) |
| `APPLE_TEAM_ID` | 10-character Team ID |

When `APPLE_CERTIFICATE` is non-empty, [`.github/workflows/release.yml`](../.github/workflows/release.yml)
runs the **signed** Tauri build step and notarizes via Apple’s notary service.
When empty, the **unsigned** step runs and the draft release notes include the
`xattr -cr` quarantine workaround.

Optional: `MINISIGN_SECRET_KEY` (unencrypted key from `minisign -G -W`) signs each
`SHA256SUMS-*.txt` for offline verification.

## Local signed build

```bash
export APPLE_ID='you@example.com'
export APPLE_PASSWORD='app-specific-password'
export APPLE_TEAM_ID='XXXXXXXXXX'
export APPLE_SIGNING_IDENTITY='Developer ID Application: …'
# Plus certificate env vars if using the same flow as CI — see Tauri docs.
npm run tauri build
```

## Verify a signed build

```bash
codesign -dv --verbose=4 "/Applications/LDK Wallet.app"
spctl -a -vv "/Applications/LDK Wallet.app"
```

Expect `Developer ID Application` and Gatekeeper acceptance (`accepted`).
Unsigned builds fail these checks — that is expected until secrets are configured.

## Release notes expectation

- **Signed releases:** release body should state that macOS is notarized; point to
  [`VERIFYING.md`](VERIFYING.md) §3.
- **Unsigned releases:** release body must keep the quarantine/`xattr` guidance.

Updating this file does not notarize artifacts by itself — credentials must be
present in the environment that runs the Release workflow.
