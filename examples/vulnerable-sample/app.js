// Sample file for the CipherChecker self-test. Deliberately quantum-vulnerable.
const crypto = require("crypto");

// Quantum-critical: RSA key exchange / signatures (Shor's algorithm).
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

function sign(payload) {
  return crypto.sign("sha256", Buffer.from(payload), privateKey);
}

// Quantum-critical: elliptic-curve Diffie-Hellman.
const ecdh = crypto.createECDH("prime256v1");
ecdh.generateKeys();

// Weakened / deprecated: MD5 and SHA-1.
function legacyFingerprint(input) {
  return crypto.createHash("md5").update(input).digest("hex");
}

function legacyEtag(input) {
  return crypto.createHash("sha1").update(input).digest("hex");
}

module.exports = { sign, legacyFingerprint, legacyEtag, publicKey };
