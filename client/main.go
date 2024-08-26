package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"

	"speech_client/pq4"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Assuming these functions are implemented in your pq4 package

func main() {
	// 1. Collect user input (simulated here)
	username := "alice"
	email := "alice@example.com"
	bio := "Crypto enthusiast"
	password := "secure_password_123"

	// 2. Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	// 3. Create encryption key
	encryptionKey := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// 4. Generate cryptographic keys
	identityPrivKey, identityPubKey, err := pq4.GenerateE521KeyPair()
	if err != nil {
		log.Fatalf("Failed to generate identity key: %v", err)
	}

	signedPreKeyPriv, signedPreKeyPub, err := pq4.GenerateE521KeyPair()
	if err != nil {
		log.Fatalf("Failed to generate signed pre-key: %v", err)
	}

	oneTimePreKeys := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		_, pubKey, err := pq4.GenerateE521KeyPair()
		if err != nil {
			log.Fatalf("Failed to generate one-time pre-key %d: %v", i, err)
		}
		oneTimePreKeys[i] = pq4.SerializePoint(pubKey)
	}

	kyberPubKey, kyberPrivKey, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate Kyber key: %v", err)
	}

	kyberPrivKeyBytes := make([]byte, kyber1024.PrivateKeySize)
	kyberPrivKey.Pack(kyberPrivKeyBytes)

	kyberPubKeyBytes := make([]byte, kyber1024.PublicKeySize)
	kyberPubKey.Pack(kyberPubKeyBytes)

	// 5. Sign the signed pre-key
	signedPreKeySignature, err := pq4.SignMessage(identityPrivKey, pq4.SerializePoint(signedPreKeyPub))
	if err != nil {
		log.Fatalf("Failed to sign pre-key: %v", err)
	}

	// 6. Encrypt private keys
	privateKeys := struct {
		IdentityKey     *big.Int
		SignedPreKey    *big.Int
		KyberPrivateKey []byte
	}{
		IdentityKey:     identityPrivKey,
		SignedPreKey:    signedPreKeyPriv,
		KyberPrivateKey: kyberPrivKeyBytes,
	}

	privateKeysBytes, err := json.Marshal(privateKeys)
	if err != nil {
		log.Fatalf("Failed to marshal private keys: %v", err)
	}

	encryptedPrivateKeys, err := pq4.Encrypt(encryptionKey, privateKeysBytes, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt private keys: %v", err)
	}

	// 7. Compute password HMAC
	authKeyReader := hkdf.New(sha512.New, encryptionKey, salt, []byte("Auth"))
	authKey := make([]byte, 32)
	if _, err := authKeyReader.Read(authKey); err != nil {
		log.Fatalf("Failed to generate auth key: %v", err)
	}
	passwordHmac := pq4.ComputeHMAC(authKey, []byte("Login"))

	// 8. Populate the request structure
	req := struct {
		Username              string   `json:"username"`
		Email                 string   `json:"email"`
		Bio                   string   `json:"bio"`
		PasswordHmac          []byte   `json:"password_hmac"`
		Salt                  []byte   `json:"salt"`
		PublicIdentityKey     []byte   `json:"public_identity_key"`
		PublicSignedPreKey    []byte   `json:"public_signed_pre_key"`
		SignedPreKeySignature []byte   `json:"signed_pre_key_signature"`
		PublicKyberKey        []byte   `json:"public_kyber_key"`
		PublicOneTimePreKeys  [][]byte `json:"public_one_time_pre_keys"`
		EncryptedPrivateKeys  []byte   `json:"encrypted_private_keys"`
	}{
		Username:              username,
		Email:                 email,
		Bio:                   bio,
		PasswordHmac:          passwordHmac,
		Salt:                  salt,
		PublicIdentityKey:     pq4.SerializePoint(identityPubKey),
		PublicSignedPreKey:    pq4.SerializePoint(signedPreKeyPub),
		SignedPreKeySignature: signedPreKeySignature,
		PublicKyberKey:        kyberPubKeyBytes,
		PublicOneTimePreKeys:  oneTimePreKeys,
		EncryptedPrivateKeys:  encryptedPrivateKeys,
	}

	// 9. Serialize and send the request
	requestBody, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("Failed to marshal request: %v", err)
	}

	println(requestBody)

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair("/Users/usmanakhmedov/FleetProjects/speech/client.crt", "/Users/usmanakhmedov/FleetProjects/speech/client.key")
	if err != nil {
		log.Fatalf("Failed to load client certificate and key: %v", err)
	}

	// Create a custom TLS configuration
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, // Only use this for development/testing!
	}

	// Create a custom HTTP client with the TLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Send the request to the server
	resp, err := client.Post("https://localhost:8443/users", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Handle the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Registration failed. Server responded with status code %d: %s", resp.StatusCode, body)
	}

	fmt.Println("Registration successful!")
	fmt.Printf("Server response: %s\n", body)
}
