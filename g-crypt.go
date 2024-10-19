package gcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

var (
    newCipher = aes.NewCipher
    readFull  = io.ReadFull
)

func genKey(password string) []byte {
    hash := sha256.Sum256([]byte(password))
    return hash[:]
}

func EncryptAES256(text, password string) (string, error) {
    if password == "" {
        return "", errors.New("password cannot be empty")
    }

    key := genKey(password)

    block, err := newCipher(key)
    if err != nil {
        return "", err
    }

    iv := make([]byte, aes.BlockSize)
    _, err = readFull(rand.Reader, iv)
    if err != nil {
        return "", err
    }

    padding := aes.BlockSize - len(text)%aes.BlockSize
    paddedText := append([]byte(text), bytes.Repeat([]byte{byte(padding)}, padding)...)

    mode := cipher.NewCBCEncrypter(block, iv)

    ciphertext := make([]byte, len(paddedText))
    mode.CryptBlocks(ciphertext, paddedText)

    result := append(iv, ciphertext...)

    return base64.StdEncoding.EncodeToString(result), nil
}

func DecryptAES256(encryptedText, password string) ([]byte, error) {
    if password == "" {
        return nil, errors.New("password cannot be empty")
    }

    key := genKey(password)

    cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
    if err != nil {
        return nil, err
    }

    block, err := newCipher(key)
    if err != nil {
        return nil, err
    }

    if len(cipherText) < aes.BlockSize {
        return nil, errors.New("cipherText too short")
    }

    iv := cipherText[:aes.BlockSize]
    cipherText = cipherText[aes.BlockSize:]

    if len(cipherText)%aes.BlockSize != 0 {
        return nil, errors.New("cipherText is not a multiple of the block size")
    }

    mode := cipher.NewCBCDecrypter(block, iv)

    decrypted := make([]byte, len(cipherText))
    mode.CryptBlocks(decrypted, cipherText)

    padding := int(decrypted[len(decrypted)-1])
    if padding > aes.BlockSize || padding == 0 {
        return nil, errors.New("invalid padding")
    }

    for i := 0; i < padding; i++ {
        if decrypted[len(decrypted)-1-i] != byte(padding) {
            return nil, errors.New("invalid padding")
        }
    }

    return decrypted[:len(decrypted)-padding], nil
}