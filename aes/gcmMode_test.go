package aes

import (
	"encoding/hex"
	"testing"
)

func TestMultiplyGF128_NISTExample(t *testing.T) {
	var x [BlockSizeBytes]byte
	var y [BlockSizeBytes]byte

	_, err := hex.Decode(x[:], []byte("0388dace60b6a392f328c2b971b2fe78"))
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	_, err = hex.Decode(y[:], []byte("66e94bd4ef8a2c3b884cfa59ca342b2e"))
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}

	want := [BlockSizeBytes]byte{0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53, 0xde, 0xb7}
	got := multiplyGF128(x, y)
	if got != want {
		t.Fatalf("multiplyGF128() = %x, want %x", got, want)
	}
}

func TestEncryptByteStreamGCM_NISTExample(t *testing.T) {
	key := make([]byte, BlockSizeBytes)
	nonce := make([]byte, BlockSizeBytes-CTRSize)
	plainText := make([]byte, BlockSizeBytes)

	_, cipherText, tag, err := encryptByteStreamGCMWithNonce(plainText, key, nonce)
	if err != nil {
		t.Fatalf("encryptByteStreamGCMWithNonce() error = %v", err)
	}

	wantCipherText := [BlockSizeBytes]byte{0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78}
	var gotCipherText [BlockSizeBytes]byte
	copy(gotCipherText[:], cipherText)
	if gotCipherText != wantCipherText {
		t.Fatalf("ciphertext = %x, want %x", gotCipherText, wantCipherText)
	}

	wantTag := [BlockSizeBytes]byte{0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf}
	var gotTag [BlockSizeBytes]byte
	copy(gotTag[:], tag)
	if gotTag != wantTag {
		t.Fatalf("tag = %x, want %x", gotTag, wantTag)
	}
}
