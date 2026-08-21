# Support

## Getting help

- **Questions, bugs, feature requests:** open an issue at
  [cipherchecker/cipherchecker-action/issues](https://github.com/cipherchecker/cipherchecker-action/issues).
- **Email:** support@cipherchecker.com
- **Security reports:** see [SECURITY.md](SECURITY.md) — email security@cipherchecker.com,
  please do not open a public issue.

We aim to acknowledge issues and email within 3 business days.

## Before you file

A few things that answer most questions:

- **Nothing is being uploaded.** The scan runs entirely on your runner. If you are seeing
  network activity, it is not from this Action.
- **A finding is a signal to review, not proof of vulnerable use.** A matched call-site
  means the primitive appears in your code, not that it is exploitable as used.
- **No findings is not a clean bill of health.** This is a detection-based scan. Absence of
  findings means nothing matched, not that the repository is quantum-safe.
- **MD5 / SHA-1 / DES / RC4** are reported as broken *classically*. They are not quantum
  problems and are worded accordingly.
- **Which files are skipped:** vendored and generated directories (`node_modules`, `vendor`,
  `dist`, `build`, `target`, `.venv`, `testdata`, `fixtures`), minified files, type
  declarations, lockfiles, tests and specs, and anything over 1 MB.

When reporting a problem, please include the version or tag you are using, the relevant
part of the job log, and the language or manifest involved.

## Licensing

This Action is licensed to end users under [Apache-2.0](LICENSE). That license governs your
use of it; there is no separate end user license agreement.

## Scope

CipherChecker performs an **assessment, not a certification**, and is not a compliance
guarantee. If you need an audit-ready CBOM and a report mapped to NIST IR 8547 / CNSA 2.0,
see [cipherchecker.com](https://cipherchecker.com/?src=gh-action-readme).
