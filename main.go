package main

import (
	"AES_Practice_go/aes"
	"os"

	"github.com/charmbracelet/log"
)

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
	demoCTR()
}
