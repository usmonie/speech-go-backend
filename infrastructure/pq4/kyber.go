package pq4

import (
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

var scheme = kyber1024.Scheme()

func GenerateKyberKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return scheme.GenerateKeyPair()
}

func KyberEncapsulate(pk kem.PublicKey) ([]byte, []byte, error) {
	return scheme.Encapsulate(pk)
}

func KyberDecapsulate(sk kem.PrivateKey, ciphertext []byte) ([]byte, error) {
	return scheme.Decapsulate(sk, ciphertext)
}
