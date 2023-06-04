package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/eddilithium2"
)

func main() {
	m := "Hello"

	argCount := len(os.Args[1:])

	if argCount > 0 {
		m = os.Args[1]
	}

	pk, sk, _ := eddilithium2.GenerateKey(nil)

	msg := []byte(m)

	var signature [eddilithium2.SignatureSize]byte
	eddilithium2.SignTo(sk, msg, signature[:])

	fmt.Printf("PQC Signatures (Ed25519-Dilithium2)\n\n")
	fmt.Printf("Message: %s \n\n", msg)
	fmt.Printf("Private key: %x [showing first 64 bytes]\n", sk.Bytes()[:64])
	fmt.Printf(" - Private key length: %d\n", len(sk.Bytes()))
	fmt.Printf("Public key: %x [showing first 64 bytes]\n", pk.Bytes()[:64])
	fmt.Printf(" - Public key length: %d\n", len(pk.Bytes()))
	fmt.Printf("Signature: %x [showing first 64 bytes]\n", signature[:64])

	fmt.Printf(" - Signature length: %d \n", len(signature))

	if !eddilithium2.Verify(pk, msg, signature[:]) {
		panic("Signature has NOT been verified!")
	} else {
		fmt.Printf("Signature has been verified!")
	}
}
