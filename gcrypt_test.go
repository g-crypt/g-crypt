package gcrypt

import (
	"testing"
)

func TestEncryptAES256(t *testing.T) {
    text := "Example text"
    password := "secret-password"

    encrypted, err := EncryptAES256(text, password)
    if err != nil {
        t.Errorf("Error encrypting: %v", err)
    }

    if encrypted == "" {
        t.Error("Encrypted text is empty")
    }
}

func TestDecryptAES256(t *testing.T) {
    text := "Example text"
    password := "secret-password"

    encrypted, err := EncryptAES256(text, password)
    if err != nil {
        t.Errorf("Error encrypting: %v", err)
    }

    decrypted, err := DecryptAES256(encrypted, password)
    if err != nil {
        t.Errorf("Error decrypting: %v", err)
    }

    if string(decrypted) != text {
        t.Errorf("Decrypted text does not match original. Got: %s, want: %s", decrypted, text)
    }
}