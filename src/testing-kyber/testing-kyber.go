package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

func control(message string) {
	// https://asecuritysite.com/ecies/go_hybrid
	// https://pkg.go.dev/github.com/cloudflare/circl@v1.3.3/hpke#example-package
	// Based on standard elliptic curves
	// Key Exchange: Curve P256
	// KDF: HKDF_SHA256
	// Encryption:
	// HPKE works for any combination of a
	// public-key encapsulation mechanism (KEM),
	// a key derivation function (KDF),
	// and an authenticated encryption scheme with additional data (AEAD).
	// HPKE_KEM_P256_HKDF_SHA256

	// define protocol params
	kemID := hpke.KEM_P256_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	info := []byte("public info string, known to both Alice and Bob")

	// define keypairs
	bob_pk, bob_sk, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Bob prepares to receive messages and announces his public key.
	Bob, err := suite.NewReceiver(bob_sk, info)
	if err != nil {
		panic(err)
	}

	// Alice uses Bob's public key.
	Alice, err := suite.NewSender(bob_pk, info)
	if err != nil {
		panic(err)
	}

	// Setup generates a new HPKE context used for Base Mode encryption.
	// Returns the Sealer and corresponding encapsulated key.
	// other than Base also Auth Mode possible
	enc, sealer, err := Alice.Setup(rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := []byte(message)
	aad := []byte("additional public data")
	ct, err := sealer.Seal(msg, aad)
	if err != nil {
		panic(err)
	}

	// Setup generates a new HPKE context used for Base Mode encryption.
	// Setup takes an encapsulated key and returns an Opener.
	opener, err := Bob.Setup(enc)
	if err != nil {
		panic(err)
	}

	ptBob, err := opener.Open(ct, aad)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Public key type:\t%s\n", bob_pk.Scheme().Name())
	fmt.Printf("Suite params: %s \n", suite.String())

	fmt.Printf("Bob's Public Key (pk) = %X\n", bob_pk)
	fmt.Printf("Bob's Private key (sk) = %X\n", bob_sk)
	fmt.Printf("Ciphertext (ct) = %X\n", ct)
	fmt.Printf("Shared Key Size:\t%d\n", hpke.KEM(kemID).Scheme().SharedKeySize())

	fmt.Printf("\n\nLength of Bob's Public Key (pk) = %d bytes \n", hpke.KEM(kemID).Scheme().PublicKeySize())
	fmt.Printf("Length of Bob's Secret Key (pk)  = %d  bytes\n", hpke.KEM(kemID).Scheme().PrivateKeySize())
	fmt.Printf("Length of Ciphertext (ct) = %d  bytes\n", len(ct))
	// fmt.Printf(" Ciphersize:\t%d\n", hpke.KEM(kemID).Scheme().CiphertextSize())
	// ct_unmarsh, _ := hpke.UnmarshalSealer(ct)
	fmt.Printf("Cipher:\t%x\n", ct)
	fmt.Printf("Plaintext:\t%s\n", ptBob)
	// Plaintext was sent successfully.
	fmt.Println(bytes.Equal(msg, ptBob))

	fmt.Printf("################################\n\n")

}

func main() {
	m := "Hello"

	argCount := len(os.Args[1:])

	if argCount > 0 {
		m = os.Args[1]
	}

	// verify plain
	control(m)

	// TODO: try using a hybrid protocol instead: https://pkg.go.dev/github.com/cloudflare/circl@v1.3.3/kem/hybrid
	kyber_scheme := kyber1024.Scheme()

	// rand.Reader
	seed := make([]byte, 48)
	_, err := rand.Read(seed)
	if err != nil {
		panic("err")
	}
	// log.Printf("random bytes: %v", seed)

	kseed := make([]byte, kyber_scheme.SeedSize())
	eseed := make([]byte, kyber_scheme.EncapsulationSeedSize())

	rand.Read(kseed)
	rand.Read(eseed)

	pk, sk := kyber_scheme.DeriveKeyPair(kseed)
	ppk, _ := pk.MarshalBinary()
	psk, _ := sk.MarshalBinary()
	ct, ss, _ := kyber_scheme.EncapsulateDeterministically(pk, eseed)
	ss2, _ := kyber_scheme.Decapsulate(sk, ct)

	fmt.Printf("Method: %s \n", m)
	fmt.Printf("Seed for key exchange: %X\n", seed)

	fmt.Printf("Public Key (pk) = %X (first 32 bytes)\n", ppk[:32])
	fmt.Printf("Private key (sk) = %X (first 32 bytes)\n", psk[:32])
	fmt.Printf("Ciphertext (ct) = %X (first 32 bytes)\n", ct[:32])
	fmt.Printf("\nShared key (Bob):\t%X\n", ss)
	fmt.Printf("Shared key (Alice):\t%X", ss2)

	fmt.Printf("\n\nLength of Public Key (pk) = %d bytes \n", len(ppk))
	fmt.Printf("Length of Secret Key (pk)  = %d  bytes\n", len(psk))
	fmt.Printf("Length of Ciphertext (ct) = %d  bytes\n", len(ct))

}
