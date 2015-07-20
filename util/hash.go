package util

import (
	"crypto/sha512"
)

// HashOutputLen is the number of bytes of output from SHA-512 to use.
const HashOutputLen = 32

// Hash hashes the provided data with SHA-512 (first HashOutputLen-byte output size).
// We use SHA-512 with the first 256 bits as output instead of SHA512/256 due to
// better compatability with NaCl.
func Hash(data ...[]byte) []byte {
	hasher := sha512.New()

	for i := 0; i < len(data); i++ {
		hasher.Write(data[i])
	}

	return hasher.Sum(nil)[:HashOutputLen]
}
