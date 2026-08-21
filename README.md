# CipherChecker — Post-Quantum Crypto Scan

[![Self-test](https://github.com/cipherchecker/cipherchecker-action/actions/workflows/self-test.yml/badge.svg)](https://github.com/cipherchecker/cipherchecker-action/actions/workflows/self-test.yml)

Scan your repository for **quantum-vulnerable cryptography** (RSA, ECDSA, ECDH, X25519, Ed25519, DSA, plus legacy MD5/SHA-1/DES/RC4) on every push or PR, and get a prioritized **NIST PQC migration plan** (FIPS 203/204/205).

**Your code never leaves the runner.** The scan runs entirely inside your CI job: no upload, no API key, no account, no network calls. Unlike the dependency scanners you already run (which do not look at cryptography at all), this finds the actual call-sites in your source.

## What it does

- 🔎 Scans **source code** (JS/TS, Python, Go, Rust, Java) for crypto call-sites **and** dependency manifests (npm, pip, go, cargo, Maven, Gemfile, Composer).
- 💬 Posts **inline annotations** on the PR diff at each quantum-critical call-site.
- 📊 Writes a **job summary** with a readiness grade and a prioritized migration plan.
- 🛡️ Optional **SARIF** output, so findings appear in the **Security → Code scanning** tab.
- 🚦 Optionally **fails the build** when quantum-vulnerable crypto is found.

## Quick start

```yaml
# .github/workflows/quantum-readiness.yml
name: Quantum readiness
on: [push, pull_request]

jobs:
  cipherchecker:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed for the SARIF upload step
    steps:
      - uses: actions/checkout@v4

      - uses: cipherchecker/cipherchecker-action@v1
        with:
          fail-on: critical          # critical | any | never
          sarif-file: cipherchecker.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cipherchecker.sarif
```

Drop the last step if you do not want Security-tab integration. A copy of this workflow lives in [`examples/quantum-readiness.yml`](examples/quantum-readiness.yml).

### Report only, never fail the build

```yaml
      - uses: cipherchecker/cipherchecker-action@v1
        with:
          fail-on: never
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `paths` | `.` | Comma-separated paths to scan, relative to the repo root. |
| `fail-on` | `critical` | Fail the job on `critical`, on `any` finding, or `never`. |
| `sarif-file` | _(none)_ | If set, write SARIF here for `upload-sarif`. |
| `max-files` | `20000` | Maximum number of files to scan. |

## Outputs

| Output | Description |
|---|---|
| `score` | Quantum-readiness score 0–100 (empty if nothing detected). |
| `grade` | Letter grade A–F, or `N/A`. |
| `critical-call-sites` | Quantum-critical crypto call-sites found in source. |
| `libraries-flagged` | Quantum-vulnerable dependencies flagged. |

```yaml
      - id: scan
        uses: cipherchecker/cipherchecker-action@v1
      - run: echo "Grade ${{ steps.scan.outputs.grade }} (${{ steps.scan.outputs.critical-call-sites }} critical sites)"
```

## What gets skipped

Vendored and generated code (`node_modules`, `vendor`, `dist`, `build`, `target`, `.venv`, `testdata`, `fixtures`, …), minified files, type declarations, lockfiles, test and spec files, and any file over 1 MB.

## Why this matters

Adversaries can capture encrypted traffic today and decrypt it once the math becomes practical — "harvest now, decrypt later". You cannot recall data that was already intercepted, but you can control how long your migration takes, and the regulatory clock is already running: **NSA CNSA 2.0 (2027)**, **NIST IR 8547** (deprecate 2030, disallow 2035), **CISA** TLS 1.3 by 2030.

Every official playbook makes the same non-skippable first step: **inventory your cryptography.** That is what this Action does, on every commit.

## Honesty

A library's presence or a matched call-site is a **signal to review**, not proof of vulnerable use. This is a detection-based scan: the absence of findings is not proof that a repository is quantum-safe. This Action performs an **assessment, not a certification**, and is not a compliance guarantee.

MD5, SHA-1, DES and RC4 are reported as broken or deprecated **classically** — no quantum computer is required — and are worded that way rather than being lumped in with the quantum-vulnerable primitives.

## Related

Need an **audit-ready CBOM (CycloneDX 1.6) + NIST IR 8547 / CNSA 2.0 compliance report** and **continuous monitoring** across your private and org repos? → **[cipherchecker.com](https://cipherchecker.com/?src=gh-action-readme)**

You can also scan any public repo in the browser, no install: **[cipherchecker.com](https://cipherchecker.com/?src=gh-action-readme)**

## Support

Open an [issue](https://github.com/cipherchecker/cipherchecker-action/issues), or email
**support@cipherchecker.com**. See [SUPPORT.md](SUPPORT.md) for what to include, and
[SECURITY.md](SECURITY.md) for security reports.

## License

Licensed to end users under [Apache-2.0](LICENSE). That license governs your use of this
Action; there is no separate end user license agreement.
