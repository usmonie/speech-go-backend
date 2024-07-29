package pq4

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
)

type PreKeyBundle struct {
	IdentityKey     *E521Point
	SignedPreKey    *E521Point
	OneTimePreKey   *E521Point
	SignedPreKeyId  uint32
	OneTimePreKeyId uint32
	SignedPreKeySig []byte
}

func GeneratePreKeyBundle(identityKey *big.Int, identityPubKey *E521Point) (*PreKeyBundle, error) {
	// Generate signed pre-key
	_, signedPreKeyPub, err := GenerateE521KeyPair()
	if err != nil {
		return nil, err
	}

	// Generate one-time pre-key
	_, oneTimePreKeyPub, err := GenerateE521KeyPair()
	if err != nil {
		return nil, err
	}

	// Sign the signed pre-key
	signedPreKeySig, err := SignMessage(identityKey, SerializePoint(signedPreKeyPub))
	if err != nil {
		return nil, err
	}

	return &PreKeyBundle{
		IdentityKey:     identityPubKey,
		SignedPreKey:    signedPreKeyPub,
		OneTimePreKey:   oneTimePreKeyPub,
		SignedPreKeyId:  generateRandomId(),
		OneTimePreKeyId: generateRandomId(),
		SignedPreKeySig: signedPreKeySig,
	}, nil
}

func PerformX3DH(ourIdentityKey *big.Int, ourIdentityPubKey, ourEphemeralPubKey *E521Point, theirBundle *PreKeyBundle) ([]byte, error) {
	ourEphemeralKey, ourEphemeralPubKey, err := GenerateE521KeyPair()
	if err != nil {
		return nil, err
	}

	// Verify the signature on the signed pre-key
	if !VerifySignature(theirBundle.IdentityKey, SerializePoint(theirBundle.SignedPreKey), theirBundle.SignedPreKeySig) {
		return nil, errors.New("invalid signed pre-key signature")
	}

	// Perform the Diffie-Hellman exchanges
	dh1 := GenerateSharedSecret(ourIdentityKey, theirBundle.SignedPreKey)
	dh2 := GenerateSharedSecret(ourEphemeralKey, theirBundle.IdentityKey)
	dh3 := GenerateSharedSecret(ourEphemeralKey, theirBundle.SignedPreKey)
	dh4 := GenerateSharedSecret(ourEphemeralKey, theirBundle.OneTimePreKey)

	// Combine the shared secrets
	sharedSecret := append(dh1, dh2...)
	sharedSecret = append(sharedSecret, dh3...)
	sharedSecret = append(sharedSecret, dh4...)

	// Generate a random salt
	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}

	// Use HKDF to derive the final shared key
	info := append(SerializePoint(ourIdentityPubKey), SerializePoint(theirBundle.IdentityKey)...)
	derivedKey, err := DeriveKey(sharedSecret, salt, info, 32)
	if err != nil {
		return nil, err
	}

	return derivedKey, nil
}

func generateRandomId() uint32 {
	var id uint32
	err := binary.Read(rand.Reader, binary.BigEndian, &id)
	if err != nil {
		return 0
	}
	return id
}
