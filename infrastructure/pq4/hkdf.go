package pq4

import (
	"crypto/sha512"
	"golang.org/x/crypto/hkdf"
	"io"
)

// DeriveKey uses HKDF-SHA512 to derive a key of the specified length
func DeriveKey(secret, salt, info []byte, keyLength int) ([]byte, error) {
	hkdfReader := hkdf.New(sha512.New, secret, salt, info)
	key := make([]byte, keyLength)
	_, err := io.ReadFull(hkdfReader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
