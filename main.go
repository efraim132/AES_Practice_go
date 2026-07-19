package main

import (
	"crypto/rand"

	"github.com/charmbracelet/log"
)

// How many bytes the counter can possibly be
// with 4 bytes, we have we will have 32 bits for the counter
// which means 2^32 bytes which can be encrypted(64gb)
// This establishes the max size of a file to be 64gb (reasonable)
const CTRSize = 4

const blockSizeBytes = 16

func generateNonce() []byte {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	return nonce
}

func generateKey() []byte {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

func main() {
	log.Info("Starting AES-128 Block Encryption Problem")

}
