package aes

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/charmbracelet/log"
)

// CTRSize How many bytes the counter can possibly be
// with 4 bytes, we have we will have 32 bits for the counter
// which means 2^32 bytes which can be encrypted(64gb)
// This establishes the max size of a file to be 64gb (reasonable)
const CTRSize = 4

const BlockSizeBytes = 16

func GenerateNonce() []byte {
	nonce := make([]byte, BlockSizeBytes-CTRSize)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	return nonce
}

func GenerateKey() []byte {
	key := make([]byte, BlockSizeBytes)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

// Generate's a keystream size in blocks
func generateKeyStream(key, nonce []byte, numOfBlocks int) ([]byte, error) {
	convertedNumOfBlocks := uint32(numOfBlocks)
	if len(nonce) != BlockSizeBytes-CTRSize {
		return nil, fmt.Errorf("nonce Incorrect Length")
	}
	if len(key) != BlockSizeBytes {
		return nil, fmt.Errorf("key Incorrect Length")
	}
	if numOfBlocks < 1 {
		return nil, fmt.Errorf("number of blocks is less than 1")
	}

	output := make([]byte, 0, BlockSizeBytes*numOfBlocks)
	for i := uint32(0); i < convertedNumOfBlocks; i++ {
		combinedPlain := make([]byte, BlockSizeBytes)
		copy(combinedPlain[:BlockSizeBytes-CTRSize], nonce)
		binary.BigEndian.PutUint32(combinedPlain[BlockSizeBytes-CTRSize:], i)

		encryptedBytes, err := EncryptBytes(key, combinedPlain) // []byte type
		if err != nil {
			return nil, err
		}
		output = append(output, encryptedBytes...)
	}

	return output, nil
}

// XORBytes based off the length of A. Generally should be the original file.
func XORBytes(a, b []byte) []byte {
	for i := 0; i < len(a); i++ {
		a[i] = a[i] ^ b[i]
	}
	return a
}

func EncryptFileCTR(filename string, key []byte) ([]byte, error) {
	if len(key) != BlockSizeBytes {
		return nil, fmt.Errorf("Key Incorrect Length")
	}

	log.Debugf("Encrypting file %s", filename)
	plainData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	fileSize := len(plainData)
	nonce := GenerateNonce()

	var cipherBlockSize int
	if fileSize%BlockSizeBytes != 0 {
		cipherBlockSize = fileSize/BlockSizeBytes + 1
	} else {
		cipherBlockSize = fileSize / BlockSizeBytes
	}

	cipherStream, err := generateKeyStream(key, nonce, cipherBlockSize)
	if err != nil {
		return nil, err
	}

	cipherData := XORBytes(plainData, cipherStream)

	fileData := append(nonce, cipherData...)
	return fileData, nil

}

func DecryptFileCTR(filename string, key []byte) ([]byte, error) {
	if len(key) != BlockSizeBytes {
		return nil, fmt.Errorf("Key Incorrect Length")
	}
	log.Debugf("Decrypting file %s", filename)
	plainData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	nonce := plainData[:BlockSizeBytes-CTRSize]
	log.Infof("Found nonce: %s", nonce)
	cipherData := plainData[BlockSizeBytes-CTRSize:]
	cipherDataLength := len(cipherData)

	var cipherBlockSize int
	if cipherDataLength%BlockSizeBytes != 0 {
		cipherBlockSize = cipherDataLength/BlockSizeBytes + 1
	} else {
		cipherBlockSize = cipherDataLength / BlockSizeBytes
	}

	cipherStream, err := generateKeyStream(key, nonce, cipherBlockSize)
	if err != nil {
		return nil, err
	}

	decryptedData := XORBytes(cipherData, cipherStream)
	return decryptedData, nil
}
