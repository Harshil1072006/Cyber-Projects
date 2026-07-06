package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// NewEphemeralKeyPair generates a fresh X25519 key pair.
func NewEphemeralKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// DeriveSessionKey computes the shared AES-256 key from ephemeral keys.
func DeriveSessionKey(myPriv *ecdh.PrivateKey, theirPub *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := myPriv.ECDH(theirPub)
	if err != nil {
		return nil, err
	}

	salt := []byte("vpnrotator-e2ee-v1")
	info := []byte("aes-256-gcm-session-key")
	r := hkdf.New(sha256.New, sharedSecret, salt, info)

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(r, aesKey); err != nil {
		return nil, err
	}

	return aesKey, nil
}
