package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptFileThenDecryptFile_RestoresOriginalBytes(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.bin")
	encryptedPath := filepath.Join(tempDir, "input.bin.enc")
	original := []byte("nonce-prefixed ciphertext must decrypt exactly")
	key := []byte("0123456789abcdef")

	err := os.WriteFile(inputPath, original, 0o600)
	if err != nil {
		t.Fatalf("write input file: %v", err)
	}

	encrypted, err := EncryptFile(inputPath, key)
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}
	err = os.WriteFile(encryptedPath, encrypted, 0o600)
	if err != nil {
		t.Fatalf("write encrypted file: %v", err)
	}

	decrypted, err := DecryptFile(encryptedPath, key)
	if err != nil {
		t.Fatalf("decrypt file: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Fatalf("round trip mismatch\n got: %x\nwant: %x", decrypted, original)
	}
}
