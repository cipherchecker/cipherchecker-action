# Security Policy

## Reporting a vulnerability

Email **security@cipherchecker.com**. Please include the version or tag, a description,
and reproduction steps. We aim to acknowledge within 3 business days.

Please do not open a public issue for a security report.

## Scope and design notes

This Action runs entirely on your runner. It makes **no network calls**, requires **no API
key**, and transmits **no source code, findings, or telemetry** anywhere. `dist/index.js`
is a self-contained bundle with **no runtime dependencies**.

If you want to verify that for yourself, the bundle is committed in this repository and can
be read directly, and the network behaviour is observable from the runner.
