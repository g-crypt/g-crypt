package gcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

func genKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func EncryptAES256(text, password string) (string, error) {
    key := genKey(password)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    iv := make([]byte, aes.BlockSize)
    _, err = io.ReadFull(rand.Reader, iv)
    if err != nil {
        return "", err
    }

    padding := aes.BlockSize - len(text)%aes.BlockSize
    paddedText := append([]byte(text), bytes.Repeat([]byte{byte(padding)}, padding)...)

    mode := cipher.NewCBCEncrypter(block, iv)

    ciphertext := make([]byte, len(paddedText))
    mode.CryptBlocks(ciphertext, paddedText)

    result := append(iv, ciphertext...)

    hexBytes := []byte(hex.EncodeToString(result))
    return base64.StdEncoding.EncodeToString(hexBytes), nil
}


func DecryptAES256(encryptedText, password string) ([]byte, error) {
    key := genKey(password)

    hexBytes, err := base64.StdEncoding.DecodeString(encryptedText)
    if err != nil {
		return nil, err
    }

    cipherBytes, err := hex.DecodeString(string(hexBytes))
    if err != nil {
        return nil, err
    }

    if len(cipherBytes) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }
    iv := cipherBytes[:aes.BlockSize]
    cipherBytes = cipherBytes[aes.BlockSize:]

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    mode := cipher.NewCBCDecrypter(block, iv)

    decrypted := make([]byte, len(cipherBytes))
    mode.CryptBlocks(decrypted, cipherBytes)

    padding := int(decrypted[len(decrypted)-1])
    if padding > aes.BlockSize || padding <= 0 {
        return nil, errors.New("invalid padding")
    }
    decrypted = decrypted[:len(decrypted)-padding]

    return decrypted, nil
}