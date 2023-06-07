package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/eddilithium2"
)

func control(message string) {
	// Testing the signature with plain Ed25519
	pk, sk, _ := ed25519.GenerateKey(nil)

	msg := []byte(message)

	// var signature [ed25519.SignatureSize]byte
	signature := ed25519.Sign(sk, msg)

	fmt.Printf("Classical Signatures (Ed25519)\n\n")
	fmt.Printf("Message: %s \n\n", msg)

	fmt.Printf("Private key: %x\n", sk)
	fmt.Printf(" - Private key length: %d\n", len(sk))
	fmt.Printf("Public key: %x\n", pk)
	fmt.Printf(" - Public key length: %d\n", len(pk))
	fmt.Printf("Signature: %x\n", signature)

	fmt.Printf(" - Signature length: %d \n", len(signature))

	if !ed25519.Verify(pk, msg, signature[:]) {
		panic("Signature has NOT been verified!\n")
	} else {
		fmt.Printf("Signature has been verified!\n")
	}
}

func main() {
	m := "Hello"

	argCount := len(os.Args[1:])

	if argCount > 0 {
		m = os.Args[1]
	}

	// verify plain ed25519
	control(m)

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
