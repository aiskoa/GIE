package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

type EncryptionLevel struct {
	Iterations int
	KeyLength  int
}

// Predefined encryption levels
var EncryptionLevels = map[string]EncryptionLevel{
	"Low":    {Iterations: 10000, KeyLength: 32},
	"Normal": {Iterations: 800000, KeyLength: 32},
	"High":   {Iterations: 12000000, KeyLength: 32},
}

// Encryption level codes for file format
var EncryptionLevelCodes = map[string]byte{
	"Low":    0,
	"Normal": 1,
	"High":   2,
}

var EncryptionLevelCodesReverse = map[byte]string{
	0: "Low",
	1: "Normal",
	2: "High",
}

func DeriveKeyFromPassword(password, salt []byte, iterations, keyLength int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLength, sha256.New)
}

func DeriveKeys(password []byte, aesSalt, hmacSalt []byte, level EncryptionLevel) (aesKey, hmacKey []byte) {
	aesKey = DeriveKeyFromPassword(password, aesSalt, level.Iterations, level.KeyLength)
	hmacKey = DeriveKeyFromPassword(password, hmacSalt, level.Iterations, level.KeyLength)
	return aesKey, hmacKey
}
