# Examples

- **`quantum-readiness.yml`** — a drop-in workflow. Copy it to
  `.github/workflows/quantum-readiness.yml` in your repository.
- **`vulnerable-sample/`** — deliberately quantum-vulnerable code (RSA, ECDSA, ECDH,
  MD5, SHA-1 across JavaScript, Python and Go, plus a manifest with flagged
  dependencies). It exists so [the self-test](../.github/workflows/self-test.yml) can
  prove on every push that the Action still detects what it claims to detect.

  **Do not copy anything from `vulnerable-sample/` into real code.** It is a fixture.
