package pq4

import (
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/sha3"
	"math/big"
)

const (
	ProtocolName    = "PQ4SpeechDoubleRatchet"
	ProtocolVersion = "1.1"
	MaxSkip         = 1000 // Maximum number of message keys that can be skipped
)

var (
	MessageKeyLabel = []byte(ProtocolName + "_MessageKey_" + ProtocolVersion)
	ChainKeyLabel   = []byte(ProtocolName + "_ChainKey_" + ProtocolVersion)
	RootKeyLabel    = []byte(ProtocolName + "_RootKey_" + ProtocolVersion)
)

type SkippedKey struct {
	MessageNumber uint32
	MessageKey    []byte
}

type DoubleRatchetState struct {
	RootKey                []byte
	SendingChainKey        []byte
	ReceivingChainKey      []byte
	SendingRatchetPrivate  *big.Int
	SendingRatchetPublic   *E521Point
	ReceivingRatchetPublic *E521Point
	SendingMessageNumber   uint32
	ReceivingMessageNumber uint32
	PreviousChainLength    uint32
	SkippedMessageKeys     map[string][]SkippedKey // Key is the serialized public key
}

func InitializeDoubleRatchet(sharedSecret []byte, remoteRatchetKey *E521Point) (*DoubleRatchetState, error) {
	if len(sharedSecret) != 32 {
		return nil, errors.New("shared secret must be 32 bytes")
	}

	sendingRatchetPrivate, sendingRatchetPublic, err := GenerateE521KeyPair()
	if err != nil {
		return nil, err
	}

	state := &DoubleRatchetState{
		RootKey:                sharedSecret,
		SendingRatchetPrivate:  sendingRatchetPrivate,
		SendingRatchetPublic:   sendingRatchetPublic,
		ReceivingRatchetPublic: remoteRatchetKey,
		SkippedMessageKeys:     make(map[string][]SkippedKey),
	}

	// Perform initial root key ratchet step
	err = state.rootKeyRatchet()
	if err != nil {
		return nil, err
	}

	return state, nil
}

func (state *DoubleRatchetState) RatchetEncrypt(plaintext []byte) ([]byte, error) {
	messageKey, err := state.deriveMessageKey(state.SendingChainKey)
	if err != nil {
		return nil, err
	}

	header := &MessageHeader{
		PublicKey:           state.SendingRatchetPublic,
		MessageNumber:       state.SendingMessageNumber,
		PreviousChainLength: state.PreviousChainLength,
	}

	headerBytes, err := header.Encode()
	if err != nil {
		return nil, err
	}

	ciphertext, err := Encrypt(messageKey, plaintext, headerBytes)
	if err != nil {
		return nil, err
	}

	state.SendingChainKey, err = state.deriveNextChainKey(state.SendingChainKey)
	if err != nil {
		return nil, err
	}
	state.SendingMessageNumber++

	return append(headerBytes, ciphertext...), nil
}

func (state *DoubleRatchetState) RatchetDecrypt(message []byte) ([]byte, error) {
	if len(message) < MessageHeaderSize {
		return nil, errors.New("message too short")
	}

	header, err := DecodeMessageHeader(message[:MessageHeaderSize])
	if err != nil {
		return nil, err
	}

	ciphertext := message[MessageHeaderSize:]

	// Check for skipped message keys
	messageKey, err := state.trySkippedMessageKeys(header, ciphertext)
	if err == nil {
		return Decrypt(messageKey, ciphertext, message[:MessageHeaderSize])
	}

	// Perform ratchet step if necessary
	if !header.PublicKey.Equals(state.ReceivingRatchetPublic) {
		err = state.doRatchetStep(header)
		if err != nil {
			return nil, err
		}
	}

	// Skip message keys if necessary
	for state.ReceivingMessageNumber < header.MessageNumber {
		skippedKey, err := state.deriveMessageKey(state.ReceivingChainKey)
		if err != nil {
			return nil, err
		}
		state.skipMessageKey(header.PublicKey, state.ReceivingMessageNumber, skippedKey)
		state.ReceivingChainKey, err = state.deriveNextChainKey(state.ReceivingChainKey)
		if err != nil {
			return nil, err
		}
		state.ReceivingMessageNumber++
	}

	messageKey, err = state.deriveMessageKey(state.ReceivingChainKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := Decrypt(messageKey, ciphertext, message[:MessageHeaderSize])
	if err != nil {
		return nil, err
	}

	state.ReceivingChainKey, err = state.deriveNextChainKey(state.ReceivingChainKey)
	if err != nil {
		return nil, err
	}
	state.ReceivingMessageNumber++

	return plaintext, nil
}

func (state *DoubleRatchetState) rootKeyRatchet() error {
	sharedSecret := GenerateSharedSecret(state.SendingRatchetPrivate, state.ReceivingRatchetPublic)
	var err error
	state.RootKey, state.SendingChainKey, err = state.deriveRootKeyAndChainKey(state.RootKey, sharedSecret)
	return err
}

func (state *DoubleRatchetState) doRatchetStep(header *MessageHeader) error {
	state.PreviousChainLength = state.SendingMessageNumber
	state.SendingMessageNumber = 0
	state.ReceivingMessageNumber = 0
	state.ReceivingRatchetPublic = header.PublicKey

	// Generate new ratchet key pair
	var err error
	state.SendingRatchetPrivate, state.SendingRatchetPublic, err = GenerateE521KeyPair()
	if err != nil {
		return err
	}

	// Perform DH and derive new root key and receiving chain key
	sharedSecret := GenerateSharedSecret(state.SendingRatchetPrivate, state.ReceivingRatchetPublic)
	state.RootKey, state.ReceivingChainKey, err = state.deriveRootKeyAndChainKey(state.RootKey, sharedSecret)
	if err != nil {
		return err
	}

	// Skip message keys to catch up with the sender
	for i := uint32(0); i < header.PreviousChainLength; i++ {
		skippedKey, err := state.deriveMessageKey(state.ReceivingChainKey)
		if err != nil {
			return err
		}
		state.skipMessageKey(header.PublicKey, i, skippedKey)
		state.ReceivingChainKey, err = state.deriveNextChainKey(state.ReceivingChainKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func (state *DoubleRatchetState) deriveMessageKey(chainKey []byte) ([]byte, error) {
	return deriveKey(chainKey, MessageKeyLabel)
}

func (state *DoubleRatchetState) deriveNextChainKey(chainKey []byte) ([]byte, error) {
	return deriveKey(chainKey, ChainKeyLabel)
}

func (state *DoubleRatchetState) deriveRootKeyAndChainKey(rootKey, sharedSecret []byte) ([]byte, []byte, error) {
	newRootKey, err := deriveKey(append(rootKey, sharedSecret...), RootKeyLabel)
	if err != nil {
		return nil, nil, err
	}
	newChainKey, err := deriveKey(append(rootKey, sharedSecret...), ChainKeyLabel)
	if err != nil {
		return nil, nil, err
	}
	return newRootKey, newChainKey, nil
}

func (state *DoubleRatchetState) skipMessageKey(publicKey *E521Point, messageNumber uint32, messageKey []byte) {
	serializedKey := SerializePoint(publicKey)
	state.SkippedMessageKeys[string(serializedKey)] = append(state.SkippedMessageKeys[string(serializedKey)], SkippedKey{
		MessageNumber: messageNumber,
		MessageKey:    messageKey,
	})

	// Delete old skipped message keys
	if len(state.SkippedMessageKeys[string(serializedKey)]) > MaxSkip {
		state.SkippedMessageKeys[string(serializedKey)] = state.SkippedMessageKeys[string(serializedKey)][1:]
	}
}

func (state *DoubleRatchetState) trySkippedMessageKeys(header *MessageHeader, ciphertext []byte) ([]byte, error) {
	serializedKey := SerializePoint(header.PublicKey)
	skippedKeys, ok := state.SkippedMessageKeys[string(serializedKey)]
	if !ok {
		return nil, errors.New("no skipped keys for this public key")
	}

	for i, skippedKey := range skippedKeys {
		if skippedKey.MessageNumber == header.MessageNumber {
			// Verify the message authenticity using the skipped key
			headerBytes, err := header.Encode()
			if err != nil {
				return nil, err
			}

			// Attempt to decrypt and verify the message
			_, err = Decrypt(skippedKey.MessageKey, ciphertext, headerBytes)
			if err != nil {
				// If decryption fails, the skipped key might not be the correct one
				continue
			}

			// Remove this skipped key
			state.SkippedMessageKeys[string(serializedKey)] = append(skippedKeys[:i], skippedKeys[i+1:]...)
			return skippedKey.MessageKey, nil
		}
	}

	return nil, errors.New("no matching skipped key found")
}

func deriveKey(inputKeyingMaterial, label []byte) ([]byte, error) {
	h := sha3.New256()
	h.Write(inputKeyingMaterial)
	h.Write(label)
	return h.Sum(nil), nil
}

type MessageHeader struct {
	PublicKey           *E521Point
	MessageNumber       uint32
	PreviousChainLength uint32
}

const MessageHeaderSize = 132 + 4 + 4 // 132 bytes for E521 point, 4 bytes each for MessageNumber and PreviousChainLength

func (h *MessageHeader) Encode() ([]byte, error) {
	encodedHeader := make([]byte, MessageHeaderSize)
	copy(encodedHeader[:132], SerializePoint(h.PublicKey))
	binary.BigEndian.PutUint32(encodedHeader[132:136], h.MessageNumber)
	binary.BigEndian.PutUint32(encodedHeader[136:140], h.PreviousChainLength)
	return encodedHeader, nil
}

func DecodeMessageHeader(data []byte) (*MessageHeader, error) {
	if len(data) != MessageHeaderSize {
		return nil, errors.New("invalid header size")
	}

	publicKey, err := DeserializePoint(data[:132])
	if err != nil {
		return nil, err
	}

	return &MessageHeader{
		PublicKey:           publicKey,
		MessageNumber:       binary.BigEndian.Uint32(data[132:136]),
		PreviousChainLength: binary.BigEndian.Uint32(data[136:140]),
	}, nil
}
