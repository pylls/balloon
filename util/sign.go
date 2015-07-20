package util

import (
	"crypto/rand"
	"errors"

	"github.com/agl/ed25519"
)

// VerificationKeyLen is the length in bytes of the verification key.
const VerificationKeyLen = 32

// SigningKeyLen is the length in bytes of the signing key.
const SigningKeyLen = 64

// Sign attempts to sign a a message with a provideded key.
func Sign(sk, message []byte) (signature []byte, err error) {
	if len(message) == 0 {
		return nil, errors.New("cannot sign an empty message")
	}
	key, err := ToByteArray64(sk)
	if err != nil {
		return nil, errors.New("invalid signing key")
	}

	signature = ed25519.Sign(key, message)[:]
	return
}

// Verify attempts to verify a signature on a message with a key.
func Verify(vk, message []byte, signature []byte) bool {
	key, err := ToByteArray32(vk)
	if err != nil {
		return false
	}
	sig, err := ToByteArray64(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(key, message, sig)
}

// GenerateSigningKeyPair attempts to generate a signature key-pair.
func GenerateSigningKeyPair() (sk, vk []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.New("failed to generate secret signing key: " + err.Error())
	}

	return priv[:], pub[:], nil
}
