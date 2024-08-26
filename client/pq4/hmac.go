package pq4

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// ComputeHMAC calculates the HMAC-SHA256 of the input data using the provided key
func ComputeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC checks if the provided MAC is valid for the given data and key
func VerifyHMAC(key, data, mac []byte) bool {
	expectedMAC := ComputeHMAC(key, data)
	return hmac.Equal(mac, expectedMAC)
}

func ArgonPassword(password, salt []byte) []byte {
	return argon2.Key(password, salt, 10_000, 64*1024, 8, 32)
}

func HmacPassword(password, salt []byte) ([]byte, error) {
	encryption_key := ArgonPassword(password, salt)
	auth_key_reader := hkdf.New(sha512.New, encryption_key, salt, []byte("Auth"))

	auth_key := make([]byte, 32)
	_, err := auth_key_reader.Read(auth_key)
	if err != nil {
		return nil, err
	}
	passwordHmac := ComputeHMAC(auth_key, []byte("Login"))

	return passwordHmac, nil
}
