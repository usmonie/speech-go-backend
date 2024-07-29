package models

type EncryptedPrivateKeys struct {
	EncryptedIdentityKey   []byte            `json:"encrypted_identity_key"`
	EncryptedSignedPreKey  []byte            `json:"encrypted_signed_pre_key"`
	EncryptedOneTimePreKey []byte            `json:"encrypted_one_time_pre_key"` // TODO: change to [][]byte
	EncryptedKyberKey      []byte            `json:"encrypted_kyber_key"`
	KeyMetadata            map[string][]byte `json:"key_metadata"`
}
