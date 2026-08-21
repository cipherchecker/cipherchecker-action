# Changelog

## v1.0.0

First public release.

- Source-code crypto scan for JS/TS, Python, Go, Rust and Java, reporting file and line.
- Dependency-manifest scan for npm, pip, go, cargo, Maven, Gemfile and Composer.
- Inline PR annotations (capped at 50 per run), job summary with readiness grade and a
  prioritized migration plan, and optional SARIF output for the Security tab.
- `fail-on` gating: `critical`, `any`, or `never`.
- Classically-broken primitives (MD5, SHA-1, DES, RC4) are reported as broken classically
  rather than described as quantum-vulnerable.
