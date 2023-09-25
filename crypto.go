package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func Encrypt(key []byte, bytes []byte) []byte {
	if len(key) != 32 {
		panic("[-] key of wrong length, 32 chars required")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("[-] Error creating AES cipher: %s", err))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("[-] Error setting GCM: %s", err))
	}

	fmt.Println("[*] Encrypting")
	nonce := make([]byte, gcm.NonceSize())
	encrypted := gcm.Seal(nonce, nonce, bytes, nil)

	return encrypted
}

func Decrypt(key []byte, bytes []byte) []byte {
	if len(key) != 32 {
		panic("[-] key of wrong length, 32 chars required")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("[-] Error creating AES cipher: %s", err))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("[-] Error setting GCM: %s", err))
	}

	nonce := bytes[:gcm.NonceSize()]
	encryptedBytes := bytes[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, encryptedBytes, nil)

	return decrypted
}
