var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// core/pqc-classifier.js
var require_pqc_classifier = __commonJS({
  "core/pqc-classifier.js"(exports2, module2) {
    var ATTACK = {
      SHOR: {
        id: "shor",
        name: "Shor's algorithm",
        breaks: "Efficiently factors large integers and solves discrete logarithms, collapsing the hard problem these schemes rely on."
      },
      GROVER: {
        id: "grover",
        name: "Grover's algorithm",
        breaks: "Quadratically speeds up brute-force search, effectively halving symmetric key strength."
      },
      NONE: {
        id: "none",
        name: "No known quantum advantage",
        breaks: "No quantum algorithm meaningfully weakens this primitive at realistic scales."
      }
    };
    var SEVERITY = {
      CRITICAL: "critical",
      // broken outright by a quantum computer
      WEAKENED: "weakened",
      // strength reduced but salvageable by larger params
      SAFE: "safe"
      // already quantum-resistant
    };
    var KB = {
      // --- Public-key: the genuinely critical cases (Shor) ---
      rsa: {
        label: "RSA",
        family: "public-key encryption / signatures",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "RSA security rests on the difficulty of factoring the product of two large primes. Shor's algorithm factors in polynomial time, so a cryptographically relevant quantum computer recovers the private key directly from the public key.",
        migrateTo: "ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures."
      },
      ecdsa: {
        label: "ECDSA",
        family: "elliptic-curve signatures",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "ECDSA relies on the elliptic-curve discrete logarithm problem. Shor's algorithm solves discrete logs efficiently, exposing the signing key. This is the same primitive that secures most TLS handshakes and nearly all blockchain wallets.",
        migrateTo: "ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) where a conservative hash-based option is preferred."
      },
      ecdh: {
        label: "ECDH",
        family: "elliptic-curve key exchange",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "Ephemeral ECDH protects session keys today, but a recorded handshake can be broken retroactively once discrete logs fall to Shor's algorithm \u2014 the core of the 'harvest now, decrypt later' risk.",
        migrateTo: "Hybrid X25519 + ML-KEM, so a session stays safe if either component holds."
      },
      x25519: {
        label: "X25519",
        family: "elliptic-curve key exchange",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "X25519 is ECDH over Curve25519. Despite its modern reputation, it relies on the elliptic-curve discrete logarithm problem and is broken by Shor's algorithm exactly like any other ECDH \u2014 a recorded handshake is decryptable later. 'Modern' does not mean 'post-quantum'.",
        migrateTo: "Hybrid X25519 + ML-KEM (FIPS 203), so the session stays safe as long as either component holds."
      },
      ed25519: {
        label: "Ed25519",
        family: "elliptic-curve signatures (EdDSA)",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "Ed25519 is EdDSA over a twisted Edwards curve. Its security rests on the elliptic-curve discrete logarithm problem, which Shor's algorithm solves efficiently, recovering the signing key. Widely assumed safe because it is modern \u2014 but it is not quantum-resistant.",
        migrateTo: "ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) for a conservative hash-based signature."
      },
      ed448: {
        label: "Ed448",
        family: "elliptic-curve signatures (EdDSA)",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "Ed448 is EdDSA over Curve448. A larger curve raises the classical security level but does nothing against Shor's algorithm, which breaks the underlying discrete-log problem regardless of curve size.",
        migrateTo: "ML-DSA (FIPS 204), or SLH-DSA (FIPS 205)."
      },
      dsa: {
        label: "DSA",
        family: "finite-field signatures",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "The Digital Signature Algorithm relies on the finite-field discrete logarithm problem, which Shor's algorithm solves efficiently. (NIST has also deprecated DSA independently of the quantum timeline.)",
        migrateTo: "ML-DSA (FIPS 204)."
      },
      dh: {
        label: "Diffie-Hellman (finite field)",
        family: "key exchange",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.SHOR,
        why: "Finite-field DH depends on the discrete logarithm problem, which Shor's algorithm solves efficiently.",
        migrateTo: "ML-KEM (FIPS 203), ideally in a hybrid construction during transition."
      },
      // --- Symmetric / hashing: weakened, not broken (Grover) ---
      "aes-128": {
        label: "AES-128",
        family: "symmetric encryption",
        severity: SEVERITY.WEAKENED,
        attack: ATTACK.GROVER,
        why: "Grover's algorithm reduces the effective search space, dropping AES-128's security margin to roughly 64 bits \u2014 uncomfortably low for long-lived data.",
        migrateTo: "AES-256, which retains ~128-bit post-quantum strength against Grover."
      },
      "aes-256": {
        label: "AES-256",
        family: "symmetric encryption",
        severity: SEVERITY.SAFE,
        attack: ATTACK.GROVER,
        why: "Even with Grover's quadratic speedup, AES-256 keeps an effective ~128-bit security level, which is considered safe for the foreseeable future.",
        migrateTo: "No change needed."
      },
      chacha20: {
        label: "ChaCha20",
        family: "symmetric encryption",
        severity: SEVERITY.SAFE,
        attack: ATTACK.GROVER,
        why: "ChaCha20 uses a 256-bit key. Grover's quadratic speedup leaves an effective ~128-bit security level, considered safe for the foreseeable future.",
        migrateTo: "No change needed."
      },
      "3des": {
        label: "3DES (Triple DES)",
        family: "symmetric encryption",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.GROVER,
        why: "Triple DES offers at most ~112-bit classical security and a 64-bit block that is vulnerable to birthday-bound (Sweet32) attacks today. Grover further erodes the key strength. NIST has deprecated 3DES regardless of the quantum timeline.",
        migrateTo: "AES-256."
      },
      des: {
        label: "DES",
        family: "symmetric encryption",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.NONE,
        why: "Single DES has a 56-bit key and is brute-forceable classically in hours. It is broken independent of quantum computing.",
        migrateTo: "AES-256."
      },
      rc4: {
        label: "RC4",
        family: "stream cipher",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.NONE,
        why: "RC4 has known statistical biases that leak plaintext and is prohibited in TLS (RFC 7465). It is broken classically.",
        migrateTo: "AES-256-GCM or ChaCha20-Poly1305."
      },
      md5: {
        label: "MD5",
        family: "hash function",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.NONE,
        why: "MD5 collisions are trivially producible classically; it must not be used for any security purpose, independent of quantum computing.",
        migrateTo: "SHA-256 or SHA-3."
      },
      sha1: {
        label: "SHA-1",
        family: "hash function",
        severity: SEVERITY.CRITICAL,
        attack: ATTACK.NONE,
        why: "SHA-1 is already broken by classical collision attacks, independent of quantum computing. It should be removed regardless of the quantum timeline.",
        migrateTo: "SHA-256 or SHA-3."
      },
      "sha-256": {
        label: "SHA-256",
        family: "hash function",
        severity: SEVERITY.SAFE,
        attack: ATTACK.GROVER,
        why: "Grover's algorithm modestly reduces collision resistance, but SHA-256 retains a comfortable margin for current use.",
        migrateTo: "No change needed; SHA-384/512 for very long-lived integrity guarantees."
      }
    };
    function classify(primitive) {
      const key = normalize(primitive);
      const entry = KB[key];
      if (!entry) {
        return {
          input: primitive,
          recognized: false,
          severity: SEVERITY.WEAKENED,
          attack: ATTACK.NONE,
          label: primitive,
          why: "Primitive not in the knowledge base. Manual review recommended before assuming it is quantum-safe.",
          migrateTo: "Review against the latest NIST PQC standards."
        };
      }
      return { input: primitive, recognized: true, ...entry };
    }
    function normalize(raw) {
      const s = String(raw).toLowerCase();
      if (s.includes("rsa")) return "rsa";
      if (s.includes("ecdsa")) return "ecdsa";
      if (s.includes("ed25519")) return "ed25519";
      if (s.includes("ed448")) return "ed448";
      if (s.includes("eddsa")) return "ed25519";
      if (s.includes("x25519") || s.includes("curve25519")) return "x25519";
      if (s.includes("ecdh")) return "ecdh";
      if (/(^|[^a-z])dsa([^a-z]|$)/.test(s)) return "dsa";
      if (/(^|[^a-z])dh([^a-z]|$)/.test(s) || s.includes("diffie")) return "dh";
      if (s.includes("3des") || s.includes("des-ede") || s.includes("triple")) return "3des";
      if (/(^|[^a-z3])des([^a-z]|$)/.test(s)) return "des";
      if (s.includes("rc4")) return "rc4";
      if (s.includes("chacha")) return "chacha20";
      if (s.includes("aes") && s.includes("128")) return "aes-128";
      if (s.includes("aes") && s.includes("256")) return "aes-256";
      if (s.includes("md5")) return "md5";
      if (s.includes("sha1") || s.includes("sha-1")) return "sha1";
      if (s.includes("sha256") || s.includes("sha-256")) return "sha-256";
      return s;
    }
    function scoreFindings(findings) {
      if (!findings.length) return { score: null, grade: "N/A", findings: [] };
      const weights = { [SEVERITY.CRITICAL]: 0, [SEVERITY.WEAKENED]: 60, [SEVERITY.SAFE]: 100 };
      const classified = findings.map(classify);
      const avg = classified.reduce((sum, f) => sum + weights[f.severity], 0) / classified.length;
      const score = Math.round(avg);
      return { score, grade: gradeFor(score), findings: classified };
    }
    function gradeFor(score) {
      if (score >= 90) return "A";
      if (score >= 75) return "B";
      if (score >= 50) return "C";
      if (score >= 25) return "D";
      return "F";
    }
    var Harvester = { classify, scoreFindings, normalize, SEVERITY, ATTACK };
    if (typeof module2 !== "undefined" && module2.exports) module2.exports = Harvester;
    if (typeof window !== "undefined") window.HarvesterCore = Harvester;
  }
});

// core/dep-scanner.js
var require_dep_scanner = __commonJS({
  "core/dep-scanner.js"(exports2, module2) {
    var { classify, scoreFindings } = require_pqc_classifier();
    var LIB_KB = {
      // --- JavaScript / npm ---
      npm: {
        "node-rsa": { primitives: ["rsa"], note: "Dedicated RSA library; keys are quantum-vulnerable." },
        "ursa": { primitives: ["rsa"], note: "OpenSSL-backed RSA bindings." },
        "jsonwebtoken": { primitives: ["rsa", "ecdsa"], note: "JWT signing defaults to RS256/ES256, both Shor-breakable." },
        "jose": { primitives: ["rsa", "ecdsa", "ecdh"], note: "JWT/JWE/JWS toolkit; RSA, ECDSA and ECDH-ES key agreement are all classical." },
        "node-jose": { primitives: ["rsa", "ecdsa"], note: "JOSE implementation; RSA/ECDSA signing." },
        "jsrsasign": { primitives: ["rsa", "ecdsa"], note: "Broad RSA/ECDSA toolkit." },
        "elliptic": { primitives: ["ecdsa", "ecdh"], note: "Elliptic-curve operations; used widely in crypto wallets." },
        "secp256k1": { primitives: ["ecdsa"], note: "secp256k1 ECDSA; Bitcoin/Ethereum signing key." },
        "@noble/curves": { primitives: ["ecdsa", "ecdh", "ed25519"], note: "Modern EC library (secp256k1, P-256, ed25519, x25519); all classical-curve and Shor-breakable." },
        "@noble/secp256k1": { primitives: ["ecdsa"], note: "secp256k1 signing; common in wallets." },
        "@noble/ed25519": { primitives: ["ed25519"], note: "Ed25519 signatures; EdDSA is Shor-breakable." },
        "eccrypto": { primitives: ["ecdsa", "ecdh"], note: "ECIES/ECDSA over secp256k1." },
        "tweetnacl": { primitives: ["x25519", "ed25519"], note: "NaCl: X25519 key exchange + Ed25519 signatures. Classically strong, not post-quantum." },
        "openpgp": { primitives: ["rsa", "ecdsa", "ecdh"], note: "OpenPGP.js; RSA and EC keys by default." },
        "sshpk": { primitives: ["rsa", "ecdsa", "ed25519"], note: "SSH key parsing/signing (RSA, ECDSA, Ed25519)." },
        "ethers": { primitives: ["ecdsa"], note: "Ethereum library; wallet signing uses secp256k1 ECDSA." },
        "web3": { primitives: ["ecdsa"], note: "Ethereum library; secp256k1 ECDSA wallet keys." },
        "bitcoinjs-lib": { primitives: ["ecdsa"], note: "Bitcoin library; secp256k1 ECDSA." },
        "crypto-js": { primitives: ["aes-128"], note: "Symmetric/hash toolkit; verify AES key size and avoid weak hashes (MD5/SHA-1 are exposed by the API)." },
        "bcrypt": { primitives: [], note: "Password hashing; not a quantum migration target, no action needed." },
        "bcryptjs": { primitives: [], note: "Password hashing; not a quantum migration target." },
        "argon2": { primitives: [], note: "Password hashing; not a quantum migration target." }
      },
      // --- Python / pip ---
      pip: {
        "pycryptodome": { primitives: ["rsa", "ecdsa", "aes-128"], note: "General crypto; check key sizes and curve usage." },
        "pycrypto": { primitives: ["rsa", "ecdsa", "aes-128"], note: "Unmaintained legacy crypto; quantum-vulnerable public-key and weak defaults." },
        "rsa": { primitives: ["rsa"], note: "Pure-Python RSA; quantum-vulnerable." },
        "ecdsa": { primitives: ["ecdsa"], note: "ECDSA signatures; Shor-breakable." },
        "fastecdsa": { primitives: ["ecdsa"], note: "Fast ECDSA over NIST/secp curves." },
        "coincurve": { primitives: ["ecdsa"], note: "libsecp256k1 bindings; ECDSA wallet signing." },
        "cryptography": { primitives: ["rsa", "ecdsa", "ecdh", "ed25519"], note: "The standard library; supports PQC via OpenSSL provider but defaults remain classical (RSA/EC/Ed25519)." },
        "pyopenssl": { primitives: ["rsa", "ecdsa"], note: "OpenSSL bindings; X.509 keys are RSA/ECDSA." },
        "m2crypto": { primitives: ["rsa", "ecdsa"], note: "OpenSSL wrapper; RSA/ECDSA." },
        "paramiko": { primitives: ["rsa", "ecdsa", "ed25519"], note: "SSH library; host/user keys are RSA, ECDSA or Ed25519." },
        "pynacl": { primitives: ["x25519", "ed25519"], note: "libsodium bindings: X25519 + Ed25519. Classically strong, not post-quantum." },
        "pyjwt": { primitives: ["rsa", "ecdsa"], note: "JWT signing defaults to RS256/ES256." },
        "python-jose": { primitives: ["rsa", "ecdsa", "ecdh"], note: "JOSE/JWT; RSA, ECDSA, ECDH-ES." },
        "authlib": { primitives: ["rsa", "ecdsa"], note: "OAuth/OIDC/JOSE; RSA/ECDSA token signing." },
        "eth-keys": { primitives: ["ecdsa"], note: "Ethereum secp256k1 ECDSA keys." },
        "web3": { primitives: ["ecdsa"], note: "Ethereum library; secp256k1 ECDSA." }
      },
      // --- Go modules (std-lib import paths + common third-party) ---
      go: {
        "crypto/rsa": { primitives: ["rsa"], note: "Standard-library RSA." },
        "crypto/ecdsa": { primitives: ["ecdsa"], note: "Standard-library ECDSA." },
        "crypto/ecdh": { primitives: ["ecdh"], note: "Standard-library ECDH." },
        "crypto/ed25519": { primitives: ["ed25519"], note: "Standard-library Ed25519; EdDSA is Shor-breakable." },
        "crypto/dsa": { primitives: ["dsa"], note: "Standard-library DSA (deprecated)." },
        "golang.org/x/crypto/ssh": { primitives: ["rsa", "ecdsa", "ed25519"], note: "SSH keys: RSA, ECDSA, Ed25519." },
        "github.com/golang-jwt/jwt": { primitives: ["rsa", "ecdsa"], note: "JWT signing (RS256/ES256)." },
        "github.com/btcsuite/btcd/btcec": { primitives: ["ecdsa"], note: "secp256k1 ECDSA (Bitcoin)." },
        "github.com/ethereum/go-ethereum/crypto": { primitives: ["ecdsa"], note: "Ethereum secp256k1 ECDSA." }
      },
      // --- Rust crates ---
      cargo: {
        "rsa": { primitives: ["rsa"], note: "RSA crate; quantum-vulnerable." },
        "ecdsa": { primitives: ["ecdsa"], note: "ECDSA crate." },
        "ed25519-dalek": { primitives: ["ed25519"], note: "Ed25519 signatures; EdDSA is Shor-breakable." },
        "x25519-dalek": { primitives: ["x25519"], note: "X25519 key exchange; classical, not post-quantum." },
        "k256": { primitives: ["ecdsa", "ecdh"], note: "secp256k1 (Bitcoin/Ethereum)." },
        "p256": { primitives: ["ecdsa", "ecdh"], note: "NIST P-256 curve operations." },
        "p384": { primitives: ["ecdsa", "ecdh"], note: "NIST P-384 curve operations." },
        "secp256k1": { primitives: ["ecdsa"], note: "libsecp256k1 bindings; ECDSA." },
        "ring": { primitives: ["rsa", "ecdsa", "ecdh", "ed25519"], note: "Common crypto crate; classical curves and RSA by default." },
        "openssl": { primitives: ["rsa", "ecdsa"], note: "OpenSSL bindings; RSA/ECDSA." },
        "rustls": { primitives: ["ecdh", "ecdsa", "rsa"], note: "TLS stack; handshake uses classical (EC)DHE + RSA/ECDSA certs." }
      },
      // --- Java / Maven & Gradle (groupId:artifactId or bare artifact) ---
      maven: {
        "org.bouncycastle:bcprov-jdk18on": { primitives: ["rsa", "ecdsa", "ecdh", "ed25519"], note: "Bouncy Castle provider; broad classical PK support (has PQC modules, but defaults are classical)." },
        "bcprov-jdk18on": { primitives: ["rsa", "ecdsa", "ecdh", "ed25519"], note: "Bouncy Castle provider." },
        "com.auth0:java-jwt": { primitives: ["rsa", "ecdsa"], note: "JWT signing (RS256/ES256)." },
        "io.jsonwebtoken:jjwt": { primitives: ["rsa", "ecdsa"], note: "JJWT; RSA/ECDSA signing." },
        "org.bouncycastle:bcpkix-jdk18on": { primitives: ["rsa", "ecdsa"], note: "Bouncy Castle PKIX/CMS; X.509 RSA/ECDSA." }
      },
      // --- Ruby / Bundler (Gemfile) ---
      gem: {
        "jwt": { primitives: ["rsa", "ecdsa"], note: "JWT signing (RS256/ES256)." },
        "openssl": { primitives: ["rsa", "ecdsa"], note: "OpenSSL bindings; RSA/ECDSA." },
        "rbnacl": { primitives: ["x25519", "ed25519"], note: "libsodium: X25519 + Ed25519; classical, not post-quantum." },
        "bcrypt": { primitives: [], note: "Password hashing; not a quantum migration target." }
      },
      // --- PHP / Composer (composer.json) ---
      composer: {
        "firebase/php-jwt": { primitives: ["rsa", "ecdsa"], note: "JWT signing (RS256/ES256)." },
        "lcobucci/jwt": { primitives: ["rsa", "ecdsa"], note: "JWT; RSA/ECDSA signing." },
        "paragonie/sodium_compat": { primitives: ["x25519", "ed25519"], note: "libsodium polyfill: X25519 + Ed25519." },
        "phpseclib/phpseclib": { primitives: ["rsa", "ecdsa"], note: "Pure-PHP RSA/EC and SSH; classical PK." }
      }
    };
    function manifestType2(filename) {
      const f = filename.toLowerCase().split("/").pop();
      if (f === "package.json") return "npm";
      if (f === "requirements.txt" || f === "pyproject.toml" || f === "pipfile" || f === "setup.py") return "pip";
      if (f === "go.mod") return "go";
      if (f === "cargo.toml") return "cargo";
      if (f === "pom.xml" || f === "build.gradle" || f === "build.gradle.kts") return "maven";
      if (f === "gemfile") return "gem";
      if (f === "composer.json") return "composer";
      return null;
    }
    var MANIFEST_FILENAMES = [
      "package.json",
      "requirements.txt",
      "pyproject.toml",
      "Pipfile",
      "setup.py",
      "go.mod",
      "Cargo.toml",
      "pom.xml",
      "build.gradle",
      "build.gradle.kts",
      "Gemfile",
      "composer.json"
    ];
    function extractPackages(type, text) {
      const names = /* @__PURE__ */ new Set();
      if (type === "npm") {
        try {
          const json = JSON.parse(text);
          for (const block of ["dependencies", "devDependencies", "peerDependencies"]) {
            if (json[block]) Object.keys(json[block]).forEach((n) => names.add(n));
          }
        } catch {
        }
        const m = text.match(/"([@a-z0-9._/-]+)"\s*:\s*"[\^~]?[0-9]/gi) || [];
        m.forEach((s) => names.add(s.split('"')[1]));
      } else if (type === "pip") {
        text.split(/\r?\n/).forEach((line) => {
          const name = line.trim().split(/[=<>!~\s\[]/)[0];
          if (name && !name.startsWith("#")) names.add(name.toLowerCase());
        });
      } else if (type === "go") {
        const requires = text.match(/[\w.\-/]+\s+v[0-9][^\s]*/g) || [];
        requires.forEach((r) => names.add(r.split(/\s+/)[0]));
        Object.keys(LIB_KB.go).filter((k) => k.startsWith("crypto/")).forEach((std) => {
          if (text.includes(std)) names.add(std);
        });
      } else if (type === "cargo") {
        const lines = text.split(/\r?\n/);
        let inDeps = false;
        for (const line of lines) {
          if (/^\s*\[.*dependencies.*\]/i.test(line)) {
            inDeps = true;
            continue;
          }
          if (/^\s*\[/.test(line)) {
            inDeps = false;
            continue;
          }
          if (inDeps) {
            const name = line.trim().split(/[\s=]/)[0];
            if (name && !name.startsWith("#")) names.add(name);
          }
        }
      } else if (type === "maven") {
        const groups = text.match(/<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>/g) || [];
        groups.forEach((g) => {
          const gm = g.match(/<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>/);
          if (gm) {
            names.add(`${gm[1].trim()}:${gm[2].trim()}`);
            names.add(gm[2].trim());
          }
        });
        const gradle = text.match(/['"]([\w.\-]+:[\w.\-]+):[\w.\-]+['"]/g) || [];
        gradle.forEach((s) => {
          const inner = s.replace(/['"]/g, "");
          const [grp, art] = inner.split(":");
          names.add(`${grp}:${art}`);
          names.add(art);
        });
      } else if (type === "gem") {
        const gems = text.match(/^\s*gem\s+['"]([^'"]+)['"]/gm) || [];
        gems.forEach((g) => {
          const m = g.match(/gem\s+['"]([^'"]+)['"]/);
          if (m) names.add(m[1].toLowerCase());
        });
      } else if (type === "composer") {
        try {
          const json = JSON.parse(text);
          for (const block of ["require", "require-dev"]) {
            if (json[block]) Object.keys(json[block]).forEach((n) => names.add(n.toLowerCase()));
          }
        } catch {
        }
        const m = text.match(/"([a-z0-9_.\-]+\/[a-z0-9_.\-]+)"\s*:/gi) || [];
        m.forEach((s) => names.add(s.split('"')[1].toLowerCase()));
      }
      return [...names];
    }
    function scanManifest(filename, text) {
      const type = manifestType2(filename);
      if (!type) return { filename, recognized: false, findings: [] };
      const packages = extractPackages(type, text);
      const kb = LIB_KB[type];
      const findings = [];
      for (const pkg of packages) {
        const entry = kb[pkg];
        if (!entry) continue;
        if (!entry.primitives.length) {
          findings.push({
            package: pkg,
            action: "none",
            note: entry.note,
            primitives: []
          });
          continue;
        }
        findings.push({
          package: pkg,
          action: "review",
          note: entry.note,
          primitives: entry.primitives.map(classify).map((c) => ({
            label: c.label,
            severity: c.severity,
            migrateTo: c.migrateTo,
            why: c.why,
            attack: c.attack && c.attack.name
          }))
        });
      }
      return { filename, type, recognized: true, packageCount: packages.length, findings };
    }
    function scanRepo2(files) {
      const manifests = files.map((f) => scanManifest(f.filename, f.text)).filter((m) => m.recognized);
      const allFindings = manifests.flatMap((m) => m.findings.filter((f) => f.action === "review"));
      const criticalFindings = allFindings.filter(
        (f) => f.primitives.some((p) => p.severity === "critical")
      );
      const flaggedPackages = new Set(allFindings.map((f) => f.package));
      const criticalPackages = new Set(criticalFindings.map((f) => f.package));
      const criticalLibs = criticalPackages.size;
      const primitiveLabels = allFindings.flatMap((f) => f.primitives.map((p) => p.label));
      const { score, grade } = scoreFindings(primitiveLabels);
      return {
        manifestsScanned: manifests.length,
        librariesFlagged: flaggedPackages.size,
        // unique packages
        criticalLibraries: criticalLibs,
        // unique packages with a critical primitive
        flaggedOccurrences: allFindings.length,
        // package x manifest occurrences
        criticalOccurrences: criticalFindings.length,
        score,
        // null when no crypto libraries were detected
        grade,
        // "N/A" when score is null
        manifests,
        summary: criticalLibs > 0 ? `${criticalLibs} ${criticalLibs > 1 ? "dependencies introduce" : "dependency introduces"} quantum-vulnerable public-key crypto. Review usage and plan migration to NIST PQC standards.` : manifests.length ? "No quantum-vulnerable crypto libraries detected in scanned manifests." : "No recognized package manifests found."
      };
    }
    function parseGitHubRef(input2) {
      if (!input2) return null;
      let s = String(input2).trim();
      s = s.replace(/^git\+/, "").replace(/\.git$/, "");
      const urlMatch = s.match(/github\.com[/:]([\w.-]+)\/([\w.-]+)/i);
      if (urlMatch) return { owner: urlMatch[1], repo: urlMatch[2] };
      const shortMatch = s.match(/^([\w.-]+)\/([\w.-]+)$/);
      if (shortMatch) return { owner: shortMatch[1], repo: shortMatch[2] };
      return null;
    }
    async function scanGitHubRepo(ref, opts = {}) {
      const gh = parseGitHubRef(ref);
      if (!gh) return { ok: false, error: "Could not parse a GitHub repo from that input. Use a URL like github.com/owner/repo or the short form owner/repo." };
      const doFetch = opts.fetchImpl || (typeof fetch !== "undefined" ? fetch : null);
      if (!doFetch) return { ok: false, error: "No fetch implementation available in this runtime." };
      const maxManifests = opts.maxManifests || 25;
      const headers = { "User-Agent": "CipherChecker-scanner/0.2", "Accept": "application/vnd.github+json" };
      if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;
      const api = `https://api.github.com/repos/${gh.owner}/${gh.repo}`;
      let repoMeta;
      try {
        const r = await doFetch(api, { headers });
        if (r.status === 404) return { ok: false, error: `Repository ${gh.owner}/${gh.repo} not found (it may be private or misspelled).` };
        if (r.status === 403) return { ok: false, error: "GitHub API rate limit reached (60 requests/hour unauthenticated). Add a token to raise the limit.", rateLimited: true };
        if (!r.ok) return { ok: false, error: `GitHub API returned ${r.status} for the repository.` };
        repoMeta = await r.json();
      } catch (e) {
        return { ok: false, error: `Network error reaching GitHub: ${e.message}` };
      }
      const branch = repoMeta.default_branch || "main";
      let tree;
      try {
        const r = await doFetch(`${api}/git/trees/${encodeURIComponent(branch)}?recursive=1`, { headers });
        if (r.status === 403) return { ok: false, error: "GitHub API rate limit reached while reading the file tree.", rateLimited: true };
        if (!r.ok) return { ok: false, error: `Could not read the repository file tree (${r.status}).` };
        tree = await r.json();
      } catch (e) {
        return { ok: false, error: `Network error reading the file tree: ${e.message}` };
      }
      const wanted = new Set(MANIFEST_FILENAMES.map((n) => n.toLowerCase()));
      const manifestPaths = (tree.tree || []).filter((node) => node.type === "blob" && wanted.has((node.path.split("/").pop() || "").toLowerCase())).map((node) => node.path).sort((a, b) => a.split("/").length - b.split("/").length).slice(0, maxManifests);
      if (!manifestPaths.length) {
        return {
          ok: true,
          repo: `${gh.owner}/${gh.repo}`,
          branch,
          truncated: !!tree.truncated,
          manifestsScanned: 0,
          librariesFlagged: 0,
          criticalLibraries: 0,
          flaggedOccurrences: 0,
          criticalOccurrences: 0,
          manifests: [],
          summary: "No recognized package manifests found in this repository."
        };
      }
      const files = [];
      for (const path2 of manifestPaths) {
        try {
          const raw = await doFetch(`https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/${encodeURIComponent(branch)}/${path2.split("/").map(encodeURIComponent).join("/")}`, {
            headers: { "User-Agent": headers["User-Agent"] }
          });
          if (raw.ok) files.push({ filename: path2, text: await raw.text() });
        } catch {
        }
      }
      const result = scanRepo2(files);
      return {
        ok: true,
        repo: `${gh.owner}/${gh.repo}`,
        branch,
        truncated: !!tree.truncated,
        manifestPaths,
        ...result
      };
    }
    var DepScanner = { manifestType: manifestType2, extractPackages, scanManifest, scanRepo: scanRepo2, parseGitHubRef, scanGitHubRepo, MANIFEST_FILENAMES, LIB_KB };
    if (typeof module2 !== "undefined" && module2.exports) module2.exports = DepScanner;
  }
});

// core/source-scanner.js
var require_source_scanner = __commonJS({
  "core/source-scanner.js"(exports2, module2) {
    var { classify, scoreFindings } = require_pqc_classifier();
    var { parseGitHubRef } = require_dep_scanner();
    var SOURCE_EXT = /* @__PURE__ */ new Set(["js", "mjs", "cjs", "jsx", "ts", "tsx", "py", "go", "rs", "java"]);
    var SKIP_PATH = /(^|\/)(node_modules|vendor|dist|build|\.git|testdata|__tests__|fixtures)\//i;
    var SKIP_FILE2 = /(\.min\.[a-z]+$|\.d\.ts$|[._-](test|spec)\.[a-z]+$)/i;
    var LANG = {
      js: ["js", "mjs", "cjs", "jsx", "ts", "tsx"],
      py: ["py"],
      go: ["go"],
      rust: ["rs"],
      java: ["java"]
    };
    function langForFile2(filename) {
      if (typeof filename !== "string" || !filename) return null;
      const ext = (filename.split(".").pop() || "").toLowerCase();
      for (const [lang, exts] of Object.entries(LANG)) if (exts.includes(ext)) return lang;
      return null;
    }
    var RULES = {
      js: [
        { primitive: "RSA", re: /generateKeyPair(Sync)?\(\s*['"]rsa['"]|new\s+NodeRSA\b|\bnode-rsa\b|['"]RS(256|384|512)['"]/i, note: "RSA key generation or RS* JWT signing" },
        { primitive: "ECDSA", re: /generateKeyPair(Sync)?\(\s*['"]ec['"]|['"]ES(256|384|512)['"]|\becdsa\b/i, note: "EC key / ES* JWT signing / ECDSA" },
        { primitive: "ECDH", re: /createECDH\(/i, note: "Diffie-Hellman over an elliptic curve" },
        { primitive: "X25519", re: /\bx25519\b|curve25519/i, note: "X25519 / Curve25519 key agreement" },
        { primitive: "Ed25519", re: /\bed25519\b/i, note: "Ed25519 (EdDSA) signing" },
        { primitive: "DH", re: /createDiffieHellman\(/i, note: "finite-field Diffie-Hellman" },
        { primitive: "MD5", re: /createHash\(\s*['"]md5['"]/i, note: "MD5 hashing" },
        { primitive: "SHA-1", re: /createHash\(\s*['"]sha-?1['"]/i, note: "SHA-1 hashing" },
        { primitive: "3DES", re: /createCipheriv\(\s*['"]des-ede3|['"]des3/i, note: "Triple DES cipher" },
        { primitive: "DES", re: /createCipheriv\(\s*['"]des['"]|['"]des-cbc/i, note: "single DES cipher" },
        { primitive: "RC4", re: /createCipheriv\(\s*['"]rc4/i, note: "RC4 stream cipher" },
        { primitive: "AES-128", re: /createCipheriv\(\s*['"]aes-128/i, note: "AES-128 cipher" }
      ],
      py: [
        { primitive: "RSA", re: /\brsa\.(generate_private_key|newkeys)\b|RSAPrivateKey|padding\.(PSS|OAEP)|algorithm\s*=\s*['"]RS(256|384|512)['"]/i, note: "RSA key / padding / RS* JWT" },
        { primitive: "ECDSA", re: /\bec\.generate_private_key\b|\bECDSA\b|algorithm\s*=\s*['"]ES(256|384|512)['"]/, note: "EC key / ECDSA / ES* JWT" },
        { primitive: "Ed25519", re: /Ed25519(PrivateKey|PublicKey)|\bed25519\b/i, note: "Ed25519 (EdDSA)" },
        { primitive: "X25519", re: /X25519(PrivateKey|PublicKey)|\bx25519\b/i, note: "X25519 key agreement" },
        { primitive: "DSA", re: /\bdsa\.generate_private_key\b|\bDSAPrivateKey\b/, note: "DSA signing" },
        { primitive: "DH", re: /\bdh\.generate_parameters\b|DHParameterNumbers/i, note: "finite-field Diffie-Hellman" },
        { primitive: "MD5", re: /hashlib\.md5\(/i, note: "MD5 hashing" },
        { primitive: "SHA-1", re: /hashlib\.sha1\(/i, note: "SHA-1 hashing" },
        { primitive: "3DES", re: /algorithms\.TripleDES\b/, note: "Triple DES cipher" },
        { primitive: "RC4", re: /algorithms\.ARC4\b/, note: "RC4 stream cipher" }
      ],
      go: [
        { primitive: "RSA", re: /\brsa\.(GenerateKey|SignPKCS1v15|SignPSS|EncryptOAEP|DecryptOAEP)\b/, note: "crypto/rsa usage" },
        { primitive: "ECDSA", re: /\becdsa\.(GenerateKey|Sign|SignASN1|Verify)\b/, note: "crypto/ecdsa usage" },
        { primitive: "X25519", re: /ecdh\.X25519\(|\bx25519\b/i, note: "X25519 key agreement" },
        { primitive: "ECDH", re: /\becdh\.(P256|P384|P521|GenerateKey)\b/, note: "elliptic-curve Diffie-Hellman" },
        { primitive: "Ed25519", re: /\bed25519\.(GenerateKey|Sign)\b/, note: "Ed25519 signing" },
        { primitive: "DSA", re: /\bdsa\.(GenerateKey|Sign)\b/, note: "crypto/dsa usage" },
        { primitive: "MD5", re: /\bmd5\.(New|Sum)\b/, note: "MD5 hashing" },
        { primitive: "SHA-1", re: /\bsha1\.(New|Sum)\b/, note: "SHA-1 hashing" },
        { primitive: "3DES", re: /des\.NewTripleDESCipher\(/, note: "Triple DES cipher" },
        { primitive: "DES", re: /des\.NewCipher\(/, note: "single DES cipher" },
        { primitive: "RC4", re: /rc4\.NewCipher\(/, note: "RC4 stream cipher" }
      ],
      rust: [
        { primitive: "RSA", re: /RsaPrivateKey|RsaPublicKey/, note: "RSA key usage" },
        { primitive: "ECDSA", re: /\becdsa::|ecdsa::SigningKey/i, note: "ECDSA usage" },
        { primitive: "Ed25519", re: /\bed25519\b/i, note: "Ed25519 (EdDSA)" },
        { primitive: "X25519", re: /\bx25519\b/i, note: "X25519 key agreement" },
        { primitive: "MD5", re: /\bMd5\b/, note: "MD5 hashing" },
        { primitive: "SHA-1", re: /\bSha1\b/, note: "SHA-1 hashing" }
      ],
      java: [
        { primitive: "RSA", re: /getInstance\(\s*"RSA"|"(SHA\d+|MD5|SHA-1)with?RSA"|"RS(256|384|512)"/, note: "RSA key / signature" },
        { primitive: "ECDSA", re: /getInstance\(\s*"EC"|"(SHA\d+)with?ECDSA"|"ES(256|384|512)"/, note: "EC key / ECDSA signature" },
        { primitive: "DSA", re: /getInstance\(\s*"DSA"|"(SHA\d+)with?DSA"/, note: "DSA signature" },
        { primitive: "MD5", re: /getInstance\(\s*"MD5"/, note: "MD5 hashing" },
        { primitive: "SHA-1", re: /getInstance\(\s*"SHA-?1"/, note: "SHA-1 hashing" },
        { primitive: "3DES", re: /getInstance\(\s*"DESede/, note: "Triple DES cipher" },
        { primitive: "DES", re: /getInstance\(\s*"DES[^e]/, note: "single DES cipher" },
        { primitive: "RC4", re: /getInstance\(\s*"(RC4|ARCFOUR)/, note: "RC4 stream cipher" }
      ]
    };
    var SKIP_LINE = /^\s*(\/\/|#|\*)/;
    function detectInSource(filename, text) {
      const lang = langForFile2(filename);
      if (!lang) return [];
      const rules = RULES[lang];
      const out = [];
      const lines = String(text).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 400) continue;
        const commented = SKIP_LINE.test(line);
        for (const r of rules) {
          if (r.re.test(line)) {
            out.push({ primitive: r.primitive, line: i + 1, snippet: line.trim().slice(0, 160), note: r.note, commented });
          }
        }
      }
      return out;
    }
    function scanSourceFiles2(files) {
      const byPrim = /* @__PURE__ */ new Map();
      let filesWithFindings = 0;
      for (const f of files) {
        const hits = detectInSource(f.filename, f.text).filter((h) => !h.commented);
        if (hits.length) filesWithFindings++;
        for (const h of hits) {
          const c = classify(h.primitive);
          const entry = byPrim.get(c.label) || { label: c.label, severity: c.severity, attack: c.attack && c.attack.name, why: c.why, migrateTo: c.migrateTo, locations: [] };
          entry.locations.push({ file: f.filename, line: h.line, snippet: h.snippet, note: h.note });
          byPrim.set(c.label, entry);
        }
      }
      const findings = [...byPrim.values()].map((e) => ({ ...e, count: e.locations.length })).sort((a, b) => ({ critical: 0, weakened: 1, safe: 2 })[a.severity] - { critical: 0, weakened: 1, safe: 2 }[b.severity]);
      const { score, grade } = scoreFindings(findings.flatMap((f) => Array(f.count).fill(f.label)));
      const criticalSites = findings.filter((f) => f.severity === "critical").reduce((n, f) => n + f.count, 0);
      return {
        filesScanned: files.length,
        filesWithFindings,
        callSites: findings.reduce((n, f) => n + f.count, 0),
        criticalCallSites: criticalSites,
        score,
        grade,
        findings,
        summary: criticalSites > 0 ? `${criticalSites} quantum-vulnerable crypto call-site${criticalSites === 1 ? "" : "s"} found across ${filesWithFindings} file${filesWithFindings === 1 ? "" : "s"}. Each is a usage signal \u2014 confirm at the cited line.` : findings.length ? "Only weakened-or-safe crypto call-sites were detected; no quantum-critical usage in the scanned source." : "No recognized crypto call-sites detected in the scanned source."
      };
    }
    async function scanGitHubSource(ref, opts = {}) {
      const gh = parseGitHubRef(ref);
      if (!gh) return { ok: false, error: "Could not parse a GitHub repo from that input (use github.com/owner/repo)." };
      const doFetch = opts.fetchImpl || (typeof fetch !== "undefined" ? fetch : null);
      if (!doFetch) return { ok: false, error: "No fetch implementation available." };
      const maxFiles2 = opts.maxFiles || 40;
      const headers = { "User-Agent": "CipherChecker-scanner/0.3", "Accept": "application/vnd.github+json" };
      if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;
      const api = `https://api.github.com/repos/${gh.owner}/${gh.repo}`;
      let repoMeta;
      try {
        const r = await doFetch(api, { headers });
        if (r.status === 404) return { ok: false, error: `Repository ${gh.owner}/${gh.repo} not found (private or misspelled).` };
        if (r.status === 403) return { ok: false, error: "GitHub API rate limit reached (60/hour unauthenticated).", rateLimited: true };
        if (!r.ok) return { ok: false, error: `GitHub API returned ${r.status}.` };
        repoMeta = await r.json();
      } catch (e) {
        return { ok: false, error: `Network error reaching GitHub: ${e.message}` };
      }
      const branch = repoMeta.default_branch || "main";
      let tree;
      try {
        const r = await doFetch(`${api}/git/trees/${encodeURIComponent(branch)}?recursive=1`, { headers });
        if (r.status === 403) return { ok: false, error: "GitHub API rate limit reached reading the tree.", rateLimited: true };
        if (!r.ok) return { ok: false, error: `Could not read the file tree (${r.status}).` };
        tree = await r.json();
      } catch (e) {
        return { ok: false, error: `Network error reading the file tree: ${e.message}` };
      }
      const candidates = (tree.tree || []).filter((n) => n.type === "blob").map((n) => n.path).filter((p) => SOURCE_EXT.has((p.split(".").pop() || "").toLowerCase())).filter((p) => !SKIP_PATH.test(p) && !SKIP_FILE2.test(p));
      const CRYPTO_HINT = /(rsa|ecdsa|ecdh|ed25519|x25519|\bdsa\b|crypto|cipher|tls|ssl|jwt|jws|jwe|sign|cert|x509|keypair|pqc|kem)/i;
      const rank = (p) => (CRYPTO_HINT.test(p) ? 0 : 4) + (p.startsWith("src/") ? 0 : 1) + Math.min(p.split("/").length, 3) * 0.1;
      candidates.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
      const sourceFilesAvailable = candidates.length;
      const picked = candidates.slice(0, maxFiles2);
      const files = [];
      for (const path2 of picked) {
        try {
          const raw = await doFetch(`https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/${encodeURIComponent(branch)}/${path2.split("/").map(encodeURIComponent).join("/")}`, { headers: { "User-Agent": headers["User-Agent"] } });
          if (raw.ok) files.push({ filename: path2, text: await raw.text() });
        } catch {
        }
      }
      const result = scanSourceFiles2(files);
      return {
        ok: true,
        repo: `${gh.owner}/${gh.repo}`,
        branch,
        truncated: !!tree.truncated,
        sourceFilesAvailable,
        sourceFilesRead: files.length,
        capped: sourceFilesAvailable > files.length,
        ...result
      };
    }
    var SourceScanner = { detectInSource, scanSourceFiles: scanSourceFiles2, scanGitHubSource, langForFile: langForFile2, RULES };
    if (typeof module2 !== "undefined" && module2.exports) module2.exports = SourceScanner;
  }
});

// core/migration-planner.js
var require_migration_planner = __commonJS({
  "core/migration-planner.js"(exports2, module2) {
    var { normalize } = require_pqc_classifier();
    var TIERS = {
      A: {
        rank: 0,
        key: "A",
        urgency: "immediate",
        title: "Remove now \u2014 already broken, independent of quantum",
        rationale: "These primitives are broken by classical attacks that exist today; the quantum timeline is irrelevant. They should not be in production at all."
      },
      B: {
        rank: 1,
        key: "B",
        urgency: "high",
        title: "Migrate first \u2014 key exchange & transport (harvest-now-decrypt-later)",
        rationale: "A recorded handshake or ciphertext can be decrypted retroactively once Shor's algorithm runs on a large enough quantum computer. Anything with a multi-year confidentiality lifetime is already exposed today \u2014 this is the only tier with retroactive risk, which is why it comes first."
      },
      C: {
        rank: 2,
        key: "C",
        urgency: "medium",
        title: "Migrate next \u2014 digital signatures",
        rationale: "Signature forgery only becomes possible once a cryptographically-relevant quantum computer exists; there is no harvest-now risk. Move long-lived roots of trust (CA roots, firmware/code-signing keys) earlier, since they must outlive the threat."
      },
      D: {
        rank: 3,
        key: "D",
        urgency: "low",
        title: "Strengthen \u2014 weakened symmetric / hash",
        rationale: "Grover's algorithm only quadratically speeds up brute force, halving effective strength. Doubling the key or digest size restores a safe margin \u2014 no post-quantum algorithm required."
      }
    };
    var PRIM = {
      // Tier A — classically broken / deprecated
      sha1: { tier: "A", target: "SHA-256 or SHA-3" },
      md5: { tier: "A", target: "SHA-256 or SHA-3" },
      rc4: { tier: "A", target: "AES-256-GCM or ChaCha20-Poly1305" },
      des: { tier: "A", target: "AES-256-GCM" },
      "3des": { tier: "A", target: "AES-256-GCM" },
      dsa: { tier: "A", target: "ML-DSA (FIPS 204) \u2014 and remove DSA regardless; NIST has deprecated it" },
      // Tier B — key exchange / transport
      rsa: { tier: "B", target: "Hybrid X25519 + ML-KEM (FIPS 203) for key transport \u2014 see note for RSA used only as a signature key" },
      ecdh: { tier: "B", target: "Hybrid X25519 + ML-KEM (FIPS 203)" },
      x25519: { tier: "B", target: "Hybrid X25519 + ML-KEM (FIPS 203)" },
      dh: { tier: "B", target: "ML-KEM (FIPS 203), in a hybrid construction during transition" },
      // Tier C — signatures
      ecdsa: { tier: "C", target: "ML-DSA (FIPS 204), or SLH-DSA (FIPS 205) for a conservative hash-based option" },
      ed25519: { tier: "C", target: "ML-DSA (FIPS 204), or SLH-DSA (FIPS 205)" },
      ed448: { tier: "C", target: "ML-DSA (FIPS 204), or SLH-DSA (FIPS 205)" },
      // Tier D — weakened symmetric/hash
      "aes-128": { tier: "D", target: "AES-256" }
    };
    var ECOSYSTEM_NOTES = {
      npm: "Node's built-in crypto is gaining ML-KEM/ML-DSA; until it's stable in your runtime, use a liboqs binding (Open Quantum Safe) for the PQC primitives and keep the classical half for the hybrid.",
      pip: "The `cryptography` package exposes PQC through the OpenSSL 3.5+ provider; `liboqs-python` covers what it doesn't yet.",
      go: "Go 1.24+ ships `crypto/mlkem` (ML-KEM-768/1024). For ML-DSA use x/crypto or a liboqs binding until it lands in std.",
      cargo: "Use the RustCrypto PQC crates (`ml-kem`, `ml-dsa`) or `aws-lc-rs`, which exposes ML-KEM.",
      maven: "JDK 24+ ships ML-KEM and ML-DSA (JEP 496/497). On older JDKs, Bouncy Castle provides PQC and hybrid key exchange.",
      gem: "No first-party PQC in Ruby yet \u2014 bridge through OpenSSL 3.5+ bindings or a liboqs FFI, and plan a hybrid-TLS terminator in front of the app.",
      composer: "No first-party PQC in PHP yet \u2014 terminate hybrid TLS at the edge (OpenSSL 3.5+ / a CDN that supports X25519MLKEM768) and bridge app-level PQC via a liboqs FFI."
    };
    var GLOBAL_CAVEAT = "Verify current library support before you commit \u2014 PQC implementations are moving fast. During transition use HYBRID constructions (classical + PQC) so a session stays safe if either component holds; this is what major TLS stacks (OpenSSL 3.5+, BoringSSL/AWS-LC) and CDNs have deployed as X25519MLKEM768.";
    function buildPlan2(scan) {
      const manifests = scan && scan.manifests || [];
      const libs = [];
      for (const m of manifests) {
        for (const f of m.findings || []) {
          if (f.action !== "review") continue;
          libs.push({ package: f.package, ecosystem: m.type, where: m.filename, note: f.note, primitives: f.primitives || [] });
        }
      }
      const buckets = {};
      for (const lib of libs) {
        for (const p of lib.primitives) {
          const key = normalize(p.label);
          const meta = PRIM[key];
          if (!meta) continue;
          const tier = meta.tier;
          const b = buckets[tier] || (buckets[tier] = { primitives: /* @__PURE__ */ new Map(), packages: /* @__PURE__ */ new Set(), ecosystems: /* @__PURE__ */ new Set() });
          const pr = b.primitives.get(p.label) || { label: p.label, target: meta.target, packages: /* @__PURE__ */ new Set() };
          pr.packages.add(`${lib.package} (${lib.where})`);
          b.primitives.set(p.label, pr);
          b.packages.add(`${lib.package} (${lib.where})`);
          if (lib.ecosystem) b.ecosystems.add(lib.ecosystem);
        }
      }
      const priorities = Object.keys(buckets).map((t) => {
        const b = buckets[t];
        const tier = TIERS[t];
        return {
          tier: tier.key,
          urgency: tier.urgency,
          title: tier.title,
          rationale: tier.rationale,
          primitives: [...b.primitives.values()].map((pr) => ({
            label: pr.label,
            target: pr.target,
            packages: [...pr.packages]
          })),
          packages: [...b.packages],
          ecosystemNotes: [...b.ecosystems].map((e) => ({ ecosystem: e, note: ECOSYSTEM_NOTES[e] })).filter((x) => x.note)
        };
      }).sort((a, b) => TIERS[a.tier].rank - TIERS[b.tier].rank);
      const actionablePairs = new Set(priorities.flatMap((p) => p.packages));
      const actionable = actionablePairs.size;
      const actionablePackages = new Set(
        [...actionablePairs].map((s) => s.replace(/ \([^)]*\)$/, ""))
      ).size;
      return {
        repo: scan.repo || null,
        grade: scan.grade,
        score: scan.score,
        generatedBy: "deterministic",
        caveat: GLOBAL_CAVEAT,
        priorities,
        summary: actionable ? `${actionablePackages} dependenc${actionablePackages === 1 ? "y" : "ies"} to address${actionable > actionablePackages ? ` (${actionable} occurrences across manifests)` : ""} across ${priorities.length} priority tier${priorities.length === 1 ? "" : "s"}. Work top-down: Tier A is already broken, Tier B carries retroactive "harvest now, decrypt later" risk.` : "No actionable quantum-vulnerable dependencies were found in the scanned manifests."
      };
    }
    function planToMarkdown(plan) {
      const L = [];
      L.push(`# Post-Quantum Migration Plan${plan.repo ? ` \u2014 ${plan.repo}` : ""}`);
      if (plan.score != null) L.push(`
**Quantum readiness:** ${plan.score}/100 (grade ${plan.grade})`);
      L.push(`
${plan.summary}`);
      L.push(`
> ${plan.caveat}`);
      for (const p of plan.priorities) {
        L.push(`
## Tier ${p.tier} \u2014 ${p.title}`);
        L.push(`*Urgency: ${p.urgency}.* ${p.rationale}`);
        for (const pr of p.primitives) {
          L.push(`
- **${pr.label} \u2192 ${pr.target}**`);
          L.push(`  - Seen in: ${pr.packages.join(", ")}`);
        }
        if (p.ecosystemNotes.length) {
          L.push(`
  **Doing the work:**`);
          for (const en of p.ecosystemNotes) L.push(`  - \`${en.ecosystem}\`: ${en.note}`);
        }
      }
      L.push(`
---
*Generated by CipherChecker. Library presence is a signal to review, not proof of vulnerable use. Not a compliance guarantee.*`);
      return L.join("\n");
    }
    var Planner = { buildPlan: buildPlan2, planToMarkdown, TIERS, PRIM };
    if (typeof module2 !== "undefined" && module2.exports) module2.exports = Planner;
  }
});

// action/index.js
var fs = require("fs");
var path = require("path");
var { langForFile, scanSourceFiles } = require_source_scanner();
var { manifestType, scanRepo } = require_dep_scanner();
var { buildPlan } = require_migration_planner();
var WS = process.env.GITHUB_WORKSPACE || process.cwd();
var input = (name, def = "") => {
  const v = process.env["INPUT_" + name.toUpperCase()];
  return v == null || v === "" ? def : v;
};
var failOn = input("fail-on", "critical").toLowerCase();
var scanPaths = input("paths", ".").split(",").map((s) => s.trim()).filter(Boolean);
var sarifPath = input("sarif-file", "");
var maxFiles = parseInt(input("max-files", "20000"), 10) || 2e4;
var maxAnnotations = 50;
var SKIP_DIR = /(^|\/)(\.git|node_modules|vendor|dist|build|out|target|\.next|\.nuxt|\.venv|venv|env|__pycache__|testdata|fixtures|coverage|\.terraform)(\/|$)/i;
var SKIP_FILE = /(\.min\.[a-z]+$|\.d\.ts$|[._-](test|spec)\.[a-z0-9]+$|\.lock$|-lock\.json$)/i;
var MANIFEST_NAMES = /* @__PURE__ */ new Set([
  "package.json",
  "requirements.txt",
  "pyproject.toml",
  "pipfile",
  "setup.py",
  "go.mod",
  "cargo.toml",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "gemfile",
  "composer.json"
]);
function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  const line = `${name}=${value == null ? "" : String(value)}
`;
  if (f) fs.appendFileSync(f, line);
  else console.log("::output:: " + line.trim());
}
function summary(md) {
  const f = process.env.GITHUB_STEP_SUMMARY;
  if (f) fs.appendFileSync(f, md + "\n");
  else console.log("\n===== STEP SUMMARY =====\n" + md + "\n========================\n");
}
function annotate(level, file, line, message) {
  console.log(`::${level} file=${file},line=${line},title=CipherChecker::${message}`);
}
function walk(dir, acc) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (acc.length >= maxFiles) return;
    const full = path.join(dir, e.name);
    const rel = path.relative(WS, full).split(path.sep).join("/");
    if (SKIP_DIR.test("/" + rel + "/")) continue;
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) walk(full, acc);
    else if (e.isFile() && !SKIP_FILE.test(e.name)) acc.push({ full, rel, name: e.name.toLowerCase() });
  }
}
function severityRank(s) {
  return { critical: 0, weakened: 1, safe: 2 }[s] ?? 3;
}
function isQuantumAttacked(f) {
  return !!f.attack && !/no known quantum advantage/i.test(f.attack);
}
function findingHeadline(f) {
  return isQuantumAttacked(f) ? `${f.label} is quantum-vulnerable (${f.attack})` : `${f.label} is broken or deprecated classically (no quantum computer required)`;
}
function buildSarif(findings) {
  const ruleIds = /* @__PURE__ */ new Set();
  const rules = [];
  const results = [];
  for (const f of findings) {
    const ruleId = "PQC-" + f.label.replace(/[^A-Za-z0-9]+/g, "");
    if (!ruleIds.has(ruleId)) {
      ruleIds.add(ruleId);
      rules.push({
        id: ruleId,
        name: `QuantumVulnerable_${f.label.replace(/[^A-Za-z0-9]+/g, "")}`,
        shortDescription: { text: findingHeadline(f) },
        fullDescription: { text: f.why || `${f.label} should be migrated to a NIST PQC standard.` },
        helpUri: "https://cipherchecker.com/?src=gh-action-sarif",
        defaultConfiguration: { level: f.severity === "critical" ? "error" : "warning" },
        properties: { tags: ["cryptography", "post-quantum"], "security-severity": f.severity === "critical" ? "8.0" : "4.0" }
      });
    }
    for (const loc of f.locations) {
      results.push({
        ruleId,
        level: f.severity === "critical" ? "error" : "warning",
        message: { text: `${findingHeadline(f)} \u2014 migrate to ${f.migrateTo}. ${loc.note || ""}`.trim() },
        locations: [{ physicalLocation: { artifactLocation: { uri: loc.file }, region: { startLine: loc.line } } }]
      });
    }
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "CipherChecker", informationUri: "https://cipherchecker.com", version: "1.0.0", rules } }, results }]
  };
}
(function main() {
  const files = [];
  for (const p of scanPaths) walk(path.resolve(WS, p), files);
  const sourceFiles = [], manifestFiles = [];
  for (const f of files) {
    let text;
    try {
      if (fs.statSync(f.full).size > 1e6) continue;
      text = fs.readFileSync(f.full, "utf8");
    } catch {
      continue;
    }
    if (langForFile(f.rel)) sourceFiles.push({ filename: f.rel, text });
    if (MANIFEST_NAMES.has(f.name)) manifestFiles.push({ filename: f.rel, text });
  }
  const src = scanSourceFiles(sourceFiles);
  const deps = scanRepo(manifestFiles);
  const plan = buildPlan({ ...deps, repo: process.env.GITHUB_REPOSITORY || null });
  const grade = src.grade || deps.grade || "N/A";
  const score = src.score != null ? src.score : deps.score;
  const findingsBySeverity = (src.findings || []).slice().sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  let emitted = 0;
  for (const f of findingsBySeverity) {
    if (f.severity === "safe") continue;
    for (const loc of f.locations) {
      if (emitted >= maxAnnotations) break;
      const level = f.severity === "critical" ? "error" : "warning";
      annotate(level, loc.file, loc.line, `${findingHeadline(f)}. Migrate to ${f.migrateTo}.`);
      emitted++;
    }
    if (emitted >= maxAnnotations) break;
  }
  const totalSites = (src.findings || []).filter((f) => f.severity !== "safe").reduce((n, f) => n + f.count, 0);
  if (totalSites > emitted) console.log(`::notice::CipherChecker: ${totalSites - emitted} more call-sites not annotated (cap ${maxAnnotations}). See the job summary.`);
  const lines = [];
  lines.push(`## \u{1F510} CipherChecker \u2014 Post-Quantum Readiness`);
  lines.push(`**Grade ${grade}${score != null ? ` \xB7 ${score}/100` : ""}** \u2014 scanned **${sourceFiles.length}** source files + **${deps.manifestsScanned}** manifests. *Your code never left the runner.*`);
  lines.push(`
- **${src.criticalCallSites}** quantum-critical crypto call-site${src.criticalCallSites === 1 ? "" : "s"} in source`);
  const depOccurrences = deps.flaggedOccurrences != null ? deps.flaggedOccurrences : deps.librariesFlagged;
  lines.push(`- **${deps.librariesFlagged}** quantum-vulnerable dependenc${deps.librariesFlagged === 1 ? "y" : "ies"} flagged (${deps.criticalLibraries} critical)` + (depOccurrences > deps.librariesFlagged ? `, in **${depOccurrences}** occurrences across ${deps.manifestsScanned} manifests` : ""));
  if (src.findings && src.findings.length) {
    lines.push(`
### Call-sites (source)`);
    lines.push(`| Primitive | Severity | Sites | Migrate to |`);
    lines.push(`|---|---|---:|---|`);
    for (const f of findingsBySeverity.slice(0, 12)) {
      lines.push(`| ${f.label} | ${f.severity} | ${f.count} | ${f.migrateTo} |`);
    }
  }
  if (plan.priorities && plan.priorities.length) {
    lines.push(`
### Migration plan (prioritized)`);
    for (const p of plan.priorities) {
      lines.push(`- **Tier ${p.tier} \u2014 ${p.title}** *(${p.urgency})*: ${p.primitives.map((x) => x.label).join(", ")}`);
    }
  }
  lines.push(`
---`);
  lines.push(`\u{1F4CB} Need an **audit-ready CBOM + NIST IR 8547 / CNSA 2.0 compliance report** and **continuous monitoring** across your private/org repos? \u2192 **[cipherchecker.com](https://cipherchecker.com/?src=gh-action)**`);
  lines.push(`
<sub>Call-sites and dependencies are signals to review, not proof of vulnerable use. Not a compliance guarantee.</sub>`);
  summary(lines.join("\n"));
  if (sarifPath) {
    try {
      fs.writeFileSync(sarifPath, JSON.stringify(buildSarif(findingsBySeverity.filter((f) => f.severity !== "safe")), null, 2));
      console.log(`::notice::CipherChecker: wrote SARIF to ${sarifPath}`);
    } catch (e) {
      console.log(`::warning::CipherChecker: could not write SARIF (${e.message})`);
    }
  }
  setOutput("score", score == null ? "" : score);
  setOutput("grade", grade);
  setOutput("critical-call-sites", src.criticalCallSites);
  setOutput("libraries-flagged", deps.librariesFlagged);
  const criticalFound = src.criticalCallSites > 0 || deps.criticalLibraries > 0;
  const anyFound = totalSites > 0 || deps.librariesFlagged > 0;
  let fail = false;
  if (failOn === "critical") fail = criticalFound;
  else if (failOn === "any") fail = anyFound;
  if (fail) {
    console.log(`::error::CipherChecker: quantum-vulnerable cryptography found (fail-on=${failOn}). See annotations and the job summary.`);
    process.exit(1);
  }
  console.log(`CipherChecker: scan complete \u2014 grade ${grade}.`);
})();
