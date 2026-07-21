package main

import (
	"AES_Practice_go/aes"
	"bytes"
	goaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"time"

	"github.com/charmbracelet/log"
)

func testGoGCM() {
	filename := "icon.png"
	log.Info("Starting Go AES-GCM test", "filename", filename)

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	key := aes.GenerateKey()

	block, err := goaes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	encryptStart := time.Now()
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}
	encryptedData := gcm.Seal(nil, nonce, data, nil)
	encryptTime := time.Since(encryptStart)

	decryptStart := time.Now()
	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	decryptTime := time.Since(decryptStart)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(data, decryptedData) {
		log.Fatal("decrypted data does not match icon.png")
	}

	myEncryptStart := time.Now()
	_, _, _, err = aes.EncryptByteStreamGCM(data, key)
	myEncryptTime := time.Since(myEncryptStart)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(filename+".gcm.enc", encryptedData, 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(filename+".gcm.dec.png", decryptedData, 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("AES-GCM encryption comparison", "goEncryptTime", encryptTime, "myEncryptTime", myEncryptTime)
	log.Info("Go AES-GCM finished", "decryptTime", decryptTime)
}

func demoCTR() {
	filename := "icon.png"
	log.Info("Starting AES-128 Block Encryption Problem")
	log.Info("Encrypting File", "filename", filename)
	nonce := aes.GenerateNonce()
	key := aes.GenerateKey()

	log.Infof("Generated Key %x", key)
	log.Infof("Generated Nonce %x", nonce)

	encryptedData, err := aes.EncryptFileCTR(filename, key)
	if err != nil {
		log.Fatal(err)
	}

	encryptedFileName := filename + ".enc"

	err = os.WriteFile(encryptedFileName, encryptedData, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("Encrypted file %s written", encryptedFileName)

	log.Info("Decrypting File", "filename", encryptedFileName)
	decryptedData, err := aes.DecryptFileCTR(encryptedFileName, key)
	if err != nil {
		log.Fatal(err)
	}
	decryptedFileName := encryptedFileName + ".dec.png"
	err = os.WriteFile(decryptedFileName, decryptedData, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("Decrypted file %s written", decryptedFileName)
}

func main() {
	testGoGCM()
}
