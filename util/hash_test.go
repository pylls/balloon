package util

import (
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {
	// from https://en.wikipedia.org/wiki/SHA-2#Examples_of_SHA-2_variants
	wiki := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if hex.EncodeToString(Hash([]byte(""))) != wiki[:len(wiki)/2] {
		t.Fatal("hash of empty string differs from ref")
	}
}
