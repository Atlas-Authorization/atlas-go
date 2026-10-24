package atlas

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// Sealed secret delivery. With WithSecretRecipient("x25519:<public key>") every
// shown-once secret in a response arrives as a base64 libsodium sealed box
// (`sealed_secret`, `sealed_client_secret`, …) instead of plaintext. Opening and
// sealing use golang.org/x/crypto/nacl/box (SealAnonymous / OpenAnonymous), the
// vetted Go implementation of libsodium's crypto_box_seal.

// SealKeyPair is a key pair for sealed secret delivery.
type SealKeyPair struct {
	PublicKey [32]byte
	SecretKey [32]byte
	// Recipient is the value for WithSecretRecipient: "x25519:<base64 public key>".
	Recipient string
}

// ErrSealedBoxInvalid is returned when a sealed box does not open: it is too
// short, was sealed to another key, or was altered.
var ErrSealedBoxInvalid = errors.New("atlas: sealed box does not open")

// GenerateSealKeyPair makes a key pair for sealed secret delivery; pass
// Recipient to WithSecretRecipient and keep SecretKey private.
func GenerateSealKeyPair() (*SealKeyPair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pair := &SealKeyPair{PublicKey: *pub, SecretKey: *priv}
	pair.Recipient = "x25519:" + base64.StdEncoding.EncodeToString(pair.PublicKey[:])
	return pair, nil
}

// OpenSealedSecret opens a `sealed_*` field (base64 sealed box) from an Atlas
// response with the key pair whose Recipient the client was built with.
func OpenSealedSecret(sealedBase64 string, pair *SealKeyPair) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(sealedBase64)
	if err != nil {
		return "", ErrSealedBoxInvalid
	}
	plain, err := OpenSealedBox(sealed, pair.PublicKey, pair.SecretKey)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SealBox seals message to a recipient public key (crypto_box_seal).
func SealBox(message []byte, recipient [32]byte) ([]byte, error) {
	return box.SealAnonymous(nil, message, &recipient, rand.Reader)
}

// OpenSealedBox opens a sealed box addressed to publicKey (crypto_box_seal_open).
func OpenSealedBox(sealed []byte, publicKey, secretKey [32]byte) ([]byte, error) {
	plain, ok := box.OpenAnonymous(nil, sealed, &publicKey, &secretKey)
	if !ok {
		return nil, ErrSealedBoxInvalid
	}
	return plain, nil
}

// SecretsSealed says a response was sealed to the key named in X-Secret-Recipient
// (WithSecretRecipient): each listed field arrives as sealed_<field> instead of in
// plaintext. Open one with OpenSealedSecret.
type SecretsSealed struct {
	Algorithm string   `json:"algorithm"`
	Recipient string   `json:"recipient"`
	Fields    []string `json:"fields"`
}

// SealedFields are the sealed_* values any shown-once secret response can carry
// when the request named a recipient. The plaintext field is then empty.
type SealedFields struct {
	SealedSecret        string         `json:"sealed_secret,omitempty"`
	SealedClientSecret  string         `json:"sealed_client_secret,omitempty"`
	SealedWebhookSecret string         `json:"sealed_webhook_secret,omitempty"`
	SecretsSealed       *SecretsSealed `json:"secrets_sealed,omitempty"`
}
