# G-Crypt

Simple encryption library in Go using AES-256.

## Installation

To install the package, run the following command:

```bash
go get github.com/g-crypt/g-crypt
```

Or

```bash
go install github.com/g-crypt/g-crypt
```

### Usage

Here is an example of how to use the encryption and decryption functions provided by the g-crypt package:

```go
import (
    "fmt"
    "github.com/g-crypt/g-crypt"
)

func main() {
    text := "Hello World"
    password := "secret-password"

    // Encrypt the text
    encrypted, err := gcrypt.EncryptAES256(text, password)
    if err != nil {
        fmt.Println("Error encrypting:", err)
        return
    }
    fmt.Println("Encrypted text:", encrypted)

    // Decrypt the text
    decrypted, err := gcrypt.DecryptAES256(encrypted, password)
    if err != nil {
        fmt.Println("Error decrypting:", err)
        return
    }
    fmt.Println("Decrypted text:", string(decrypted))
}
```

### Functions
#### EncryptAES256
```go
func EncryptAES256(text, password string) (string, error)
```
Encrypts a text using AES-256.

- `text`: The text to be encrypted.
- `password`: The password used to generate the encryption key.

Returns the encrypted text in base64 or an error if it occurs.

#### DecryptAES256
```go
func DecryptAES256(encryptedText, password string) ([]byte, error)
```
Decrypts a text encrypted using AES-256.

- `encryptedText`: The encrypted text in base64.
- `password`: The password used to generate the encryption key.

Returns the decrypted text as a byte slice or an error if it occurs.