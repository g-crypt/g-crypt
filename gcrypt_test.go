package gcrypt

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"io"
	"testing"
)

func TestEncryptAES256(t *testing.T) {
    tests := []struct {
        text     string
        password string
        wantErr  bool
    }{
        {"Example text", "secret-password", false},
        {"Another example", "another-password", false},
        {"", "empty-text", false},
        {"text", "", true},
    }

    for _, tt := range tests {
        encrypted, err := EncryptAES256(tt.text, tt.password)
        if (err != nil) != tt.wantErr {
            t.Errorf("EncryptAES256() error = %v, wantErr %v", err, tt.wantErr)
            return
        }
        if !tt.wantErr && encrypted == "" {
            t.Error("Encrypted text is empty")
        }
    }
}

func TestDecryptAES256(t *testing.T) {
    tests := []struct {
        text     string
        password string
        wantErr  bool
    }{
        {"Example text", "secret-password", false},
        {"Another example", "another-password", false},
        {"", "empty-text", false},
        {"text", "", true},
    }

    for _, tt := range tests {
        if tt.password == "" {
            continue // Skip empty password case for encryption
        }

        encrypted, err := EncryptAES256(tt.text, tt.password)
        if err != nil {
            t.Errorf("Error encrypting: %v", err)
            return
        }

        decrypted, err := DecryptAES256(encrypted, tt.password)
        if (err != nil) != tt.wantErr {
            t.Errorf("DecryptAES256() error = %v, wantErr %v", err, tt.wantErr)
            return
        }
        if !tt.wantErr && string(decrypted) != tt.text {
            t.Errorf("Decrypted text does not match original. Got: %s, want: %s", decrypted, tt.text)
        }
    }
}

func TestDecryptAES256WithWrongPassword(t *testing.T) {
    text := "Example text"
    password := "secret-password"
    wrongPassword := "wrong-password"

    encrypted, err := EncryptAES256(text, password)
    if err != nil {
        t.Errorf("Error encrypting: %v", err)
    }

    _, err = DecryptAES256(encrypted, wrongPassword)
    if err == nil {
        t.Error("Expected error when decrypting with wrong password, but got none")
    }
}

func TestEncryptAES256WithEmptyPassword(t *testing.T) {
    text := "Example text"
    password := ""

    _, err := EncryptAES256(text, password)
    if err == nil {
        t.Error("Expected error when encrypting with empty password, but got none")
    }
}

func TestDecryptAES256WithEmptyPassword(t *testing.T) {
    text := "Example text"
    password := "secret-password"
    emptyPassword := ""

    encrypted, err := EncryptAES256(text, password)
    if err != nil {
        t.Errorf("Error encrypting: %v", err)
    }

    _, err = DecryptAES256(encrypted, emptyPassword)
    if err == nil {
        t.Error("Expected error when decrypting with empty password, but got none")
    }
}

func TestDecryptAES256WithInvalidBase64(t *testing.T) {
    invalidBase64 := "invalid-base64"
    password := "secret-password"

    _, err := DecryptAES256(invalidBase64, password)
    if err == nil {
        t.Error("Expected error when decrypting with invalid base64, but got none")
    }
}

func TestDecryptAES256WithInvalidHex(t *testing.T) {
    invalidHex := base64.StdEncoding.EncodeToString([]byte("invalid-hex"))
    password := "secret-password"

    _, err := DecryptAES256(invalidHex, password)
    if err == nil {
        t.Error("Expected error when decrypting with invalid hex, but got none")
    }
}

func TestDecryptAES256WithShortCiphertext(t *testing.T) {
    shortCiphertext := base64.StdEncoding.EncodeToString([]byte("short"))
    password := "secret-password"

    _, err := DecryptAES256(shortCiphertext, password)
    if err == nil {
        t.Error("Expected error when decrypting with short ciphertext, but got none")
    }
}

func TestDecryptAES256WithInvalidPadding(t *testing.T) {
    text := "Example text"
    password := "secret-password"

    encrypted, err := EncryptAES256(text, password)
    if err != nil {
        t.Errorf("Error encrypting: %v", err)
    }

    // Corromper o texto cifrado para ter um padding inválido
    encryptedBytes, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        t.Errorf("Error decoding base64: %v", err)
    }
    encryptedBytes[len(encryptedBytes)-1] = 0

    invalidEncrypted := base64.StdEncoding.EncodeToString(encryptedBytes)

    _, err = DecryptAES256(invalidEncrypted, password)
    if err == nil {
        t.Error("Expected error when decrypting with invalid padding, but got none")
    }
}

func TestEncryptAES256WithCipherError(t *testing.T) {
    // Simular erro ao criar o cipher block
    originalNewCipher := newCipher
    defer func() { newCipher = originalNewCipher }()
    newCipher = func(key []byte) (cipher.Block, error) {
        return nil, errors.New("cipher error")
    }

    _, err := EncryptAES256("text", "password")
    if err == nil || err.Error() != "cipher error" {
        t.Error("Expected cipher error, but got none or different error")
    }
}

func TestEncryptAES256WithIVError(t *testing.T) {
    // Simular erro ao ler o IV
    originalReadFull := readFull
    defer func() { readFull = originalReadFull }()
    readFull = func(r io.Reader, buf []byte) (n int, err error) {
        return 0, errors.New("IV error")
    }

    _, err := EncryptAES256("text", "password")
    if err == nil || err.Error() != "IV error" {
        t.Error("Expected IV error, but got none or different error")
    }
}