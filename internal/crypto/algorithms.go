package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

type EncryptionMethod string

const (
	AES_CTR  EncryptionMethod = "AES-CTR"
	CHACHA20 EncryptionMethod = "ChaCha20"
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

type ChaCha20Encryptor struct {
	cipher *chacha20.Cipher
}

func NewChaCha20Encryptor(key, nonce []byte) (*ChaCha20Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("ChaCha20 key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("ChaCha20 nonce must be 12 bytes, got %d", len(nonce))
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("error creating ChaCha20 cipher: %v", err)
	}

	return &ChaCha20Encryptor{cipher: cipher}, nil
}

func (e *ChaCha20Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	e.cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func (e *ChaCha20Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	e.cipher.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func (e *ChaCha20Encryptor) GetIVSize() int  { return 12 } // ChaCha20 nonce size
func (e *ChaCha20Encryptor) GetKeySize() int { return 32 } // ChaCha20 key size

// CreateEncryptor creates an encryptor based on the method
func CreateEncryptor(method EncryptionMethod, key, iv []byte) (Encryptor, error) {
	switch method {
	case AES_CTR:
		return NewAESCTREncryptor(key, iv)
	case CHACHA20:
		return NewChaCha20Encryptor(key, iv)
	default:
		return NewAESCTREncryptor(key, iv) // Default to AES-CTR
	}
}

// GetMethodCode returns a byte code for the encryption method
func GetMethodCode(method EncryptionMethod) byte {
	switch method {
	case AES_CTR:
		return 0
	case CHACHA20:
		return 1
	default:
		return 0
	}
}

// GetMethodFromCode returns the encryption method from byte code
func GetMethodFromCode(code byte) EncryptionMethod {
	switch code {
	case 0:
		return AES_CTR
	case 1:
		return CHACHA20
	default:
		return AES_CTR
	}
}

func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes: %v", err)
	}
	return bytes, nil
}

func GenerateSalt(length int) ([]byte, error) {
	return GenerateRandomBytes(length)
}

func GenerateIV(length int) ([]byte, error) {
	return GenerateRandomBytes(length)
}
