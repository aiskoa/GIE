package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// EncryptionMethod represents different encryption algorithms
type EncryptionMethod string

const (
	AES_CTR EncryptionMethod = "AES-CTR"
)

// EncryptionConfig holds configuration for encryption
type EncryptionConfig struct {
	Method     EncryptionMethod
	Level      EncryptionLevel
	Key        []byte
	IV         []byte
	Additional []byte // Additional authenticated data for AEAD
}

// Encryptor interface for different encryption methods
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	GetIVSize() int
	GetKeySize() int
}

// AESCTREncryptor implements AES-CTR encryption
type AESCTREncryptor struct {
	stream cipher.Stream
}

func NewAESCTREncryptor(key, iv []byte) (*AESCTREncryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %v", err)
	}

	stream := cipher.NewCTR(block, iv)
	return &AESCTREncryptor{stream: stream}, nil
}

func (e *AESCTREncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	e.stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func (e *AESCTREncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	e.stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func (e *AESCTREncryptor) GetIVSize() int  { return 16 }
func (e *AESCTREncryptor) GetKeySize() int { return 32 } // AES-256

// CreateEncryptor creates an encryptor based on the method
func CreateEncryptor(method EncryptionMethod, key, iv []byte) (Encryptor, error) {
	switch method {
	case AES_CTR:
		return NewAESCTREncryptor(key, iv)
	default:
		return NewAESCTREncryptor(key, iv) // Default to AES-CTR
	}
}

// GetMethodCode returns a byte code for the encryption method
func GetMethodCode(method EncryptionMethod) byte {
	switch method {
	case AES_CTR:
		return 0
	default:
		return 0
	}
}

// GetMethodFromCode returns the encryption method from byte code
func GetMethodFromCode(code byte) EncryptionMethod {
	switch code {
	case 0:
		return AES_CTR
	default:
		return AES_CTR
	}
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes: %v", err)
	}
	return bytes, nil
}

// GenerateSalt generates a random salt for key derivation
func GenerateSalt(length int) ([]byte, error) {
	return GenerateRandomBytes(length)
}

// GenerateIV generates a random initialization vector
func GenerateIV(length int) ([]byte, error) {
	return GenerateRandomBytes(length)
}
