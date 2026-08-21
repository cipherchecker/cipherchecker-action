// Sample file for the CipherChecker self-test. Deliberately quantum-vulnerable.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func main() {
	// Quantum-critical: RSA.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Quantum-critical: ECDSA over P-256.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fmt.Println(rsaKey.N.BitLen(), ecKey.Params().Name)
}
