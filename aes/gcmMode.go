package aes

import (
	"encoding/binary"
	"fmt"
)

// multiplyGF128 multiplies two 128-bit values for GHASH.
//
// GHASH uses the field defined by x^128 + x^7 + x^2 + x + 1. The values are
// stored in big-endian order, so each loop reads the next bit of y from left
// to right. value is shifted right after each bit; when a one falls off, the
// reduction constant 0xe1 represents the rest of the field polynomial.
func multiplyGF128(x, y [BlockSizeBytes]byte) [BlockSizeBytes]byte {
	var product [BlockSizeBytes]byte
	value := x

	for bitIndex := 0; bitIndex < BlockSizeBytes*8; bitIndex++ {
		byteIndex := bitIndex / 8
		bitOffset := uint(7 - bitIndex%8)
		bitIsSet := y[byteIndex]&(1<<bitOffset) != 0
		if bitIsSet {
			for byteIndex := 0; byteIndex < BlockSizeBytes; byteIndex++ {
				product[byteIndex] ^= value[byteIndex]
			}
		}

		leastSignificantBitIsSet := value[BlockSizeBytes-1]&1 != 0
		for byteIndex := BlockSizeBytes - 1; byteIndex > 0; byteIndex-- {
			value[byteIndex] = value[byteIndex]>>1 | value[byteIndex-1]<<7
		}
		value[0] >>= 1
		if leastSignificantBitIsSet {
			value[0] ^= 0xe1
		}
	}

	return product
}

// EncryptByteStreamGCM returns nonce, data, tag, err
func EncryptByteStreamGCM(data []byte, key []byte) ([]byte, []byte, []byte, error) {
	nonce := GenerateNonce()
	return encryptByteStreamGCMWithNonce(data, key, nonce)
}

// encryptByteStreamGCMWithNonce encrypts with a supplied 96-bit nonce. Keeping
// the nonce explicit makes the GCM construction testable with published vectors.
func encryptByteStreamGCMWithNonce(data, key, nonce []byte) ([]byte, []byte, []byte, error) {
	if len(key) != BlockSizeBytes {
		return nil, nil, nil, fmt.Errorf("key must be %d bytes", BlockSizeBytes)
	}
	if len(nonce) != BlockSizeBytes-CTRSize {
		return nil, nil, nil, fmt.Errorf("nonce must be %d bytes", BlockSizeBytes-CTRSize)
	}

	var zeroBlock [BlockSizeBytes]byte
	hBytes, err := EncryptBytes(key, zeroBlock[:])
	if err != nil {
		return nil, nil, nil, err
	}
	var h [BlockSizeBytes]byte
	copy(h[:], hBytes)

	var j0 [BlockSizeBytes]byte
	copy(j0[:], nonce)
	j0[BlockSizeBytes-1] = 1

	cipherData, err := encryptGCMCounterMode(data, key, j0)
	if err != nil {
		return nil, nil, nil, err
	}

	ghash := ghashCiphertext(cipherData, h)
	tagMask, err := EncryptBytes(key, j0[:])
	if err != nil {
		return nil, nil, nil, err
	}

	tag := make([]byte, BlockSizeBytes)
	for byteIndex := 0; byteIndex < BlockSizeBytes; byteIndex++ {
		tag[byteIndex] = tagMask[byteIndex] ^ ghash[byteIndex]
	}

	return nonce, cipherData, tag, nil
}

// encryptGCMCounterMode encrypts data with GCM's counter sequence. J0 is used
// only for the tag mask, so the first data block uses inc32(J0).
func encryptGCMCounterMode(data, key []byte, j0 [BlockSizeBytes]byte) ([]byte, error) {
	cipherData := make([]byte, len(data))
	counter := j0
	incrementGCMCounter(&counter)

	for blockStart := 0; blockStart < len(data); blockStart += BlockSizeBytes {
		keyStream, err := EncryptBytes(key, counter[:])
		if err != nil {
			return nil, err
		}

		blockEnd := blockStart + BlockSizeBytes
		if blockEnd > len(data) {
			blockEnd = len(data)
		}
		for byteIndex := blockStart; byteIndex < blockEnd; byteIndex++ {
			cipherData[byteIndex] = data[byteIndex] ^ keyStream[byteIndex-blockStart]
		}

		incrementGCMCounter(&counter)
	}

	return cipherData, nil
}

func incrementGCMCounter(counter *[BlockSizeBytes]byte) {
	value := binary.BigEndian.Uint32(counter[BlockSizeBytes-CTRSize:])
	binary.BigEndian.PutUint32(counter[BlockSizeBytes-CTRSize:], value+1)
}

// ghashCiphertext hashes ciphertext with no additional authenticated data.
func ghashCiphertext(cipherData []byte, h [BlockSizeBytes]byte) [BlockSizeBytes]byte {
	var ghash [BlockSizeBytes]byte

	for blockStart := 0; blockStart < len(cipherData); blockStart += BlockSizeBytes {
		var block [BlockSizeBytes]byte
		blockEnd := blockStart + BlockSizeBytes
		if blockEnd > len(cipherData) {
			blockEnd = len(cipherData)
		}
		copy(block[:], cipherData[blockStart:blockEnd])

		for byteIndex := 0; byteIndex < BlockSizeBytes; byteIndex++ {
			ghash[byteIndex] ^= block[byteIndex]
		}
		ghash = multiplyGF128(ghash, h)
	}

	var lengthBlock [BlockSizeBytes]byte
	binary.BigEndian.PutUint64(lengthBlock[8:], uint64(len(cipherData))*8)
	for byteIndex := 0; byteIndex < BlockSizeBytes; byteIndex++ {
		ghash[byteIndex] ^= lengthBlock[byteIndex]
	}

	return multiplyGF128(ghash, h)
}
