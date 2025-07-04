package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/pbkdf2"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// Check if a file path was passed as a command-line argument
	if len(os.Args) > 1 {
		filePath := os.Args[1]
		if strings.HasSuffix(strings.ToLower(filePath), ".gie") {
			// Emit an event to the frontend to handle the file
			runtime.EventsEmit(ctx, "file-open", filePath)
		}
	}
}

// SelectFile opens a file dialog to select a file.
func (a *App) SelectFile() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select File",
	})
}

const (
	ChunkSize = 1024 * 1024 // 1 MB
	CTRIVSize = 16          // AES-CTR IV size
	HMACSize  = 32          // SHA256 HMAC size
)

// EncryptionLevel defines parameters for different encryption strengths.
type EncryptionLevel struct {
	Iterations int
	KeyLength  int // in bytes
}

var EncryptionLevels = map[string]EncryptionLevel{
	"Low":    {Iterations: 10000, KeyLength: 16},   // AES-128
	"Normal": {Iterations: 800000, KeyLength: 32},  // AES-256
	"High":   {Iterations: 12000000, KeyLength: 32}, // AES-256
}

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

// EncryptFile encrypts a single file using AES-CTR and HMAC-SHA256.
func (a *App) EncryptFile(inputFile string, password string, hint string, encryptionLevel string, channel int) string {
	if password == "" {
		return "Encryption failed: password cannot be empty."
	}
	passwordBytes := []byte(password)
	hintBytes := []byte(hint)

	levelParams, ok := EncryptionLevels[encryptionLevel]
	if !ok {
		levelParams = EncryptionLevels["Normal"]
	}
	encryptionLevelCode, ok := EncryptionLevelCodes[encryptionLevel]
	if !ok {
		encryptionLevelCode = EncryptionLevelCodes["Normal"]
	}

	outputFile := inputFile + ".gie"
	tempOutputFile := outputFile + ".tmp"

	aesKeySalt, err := GenerateSalt(16)
	if err != nil {
		return fmt.Sprintf("error generating AES key salt: %v", err)
	}
	hmacKeySalt, err := GenerateSalt(16)
	if err != nil {
		return fmt.Sprintf("error generating HMAC key salt: %v", err)
	}

	aesKey := DeriveKeyFromPassword(passwordBytes, aesKeySalt, levelParams.Iterations, levelParams.KeyLength)
	hmacKey := DeriveKeyFromPassword(passwordBytes, hmacKeySalt, levelParams.Iterations, levelParams.KeyLength)

	ctrIV, err := GenerateIV(CTRIVSize)
	if err != nil {
		return fmt.Sprintf("error generating CTR IV: %v", err)
	}

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Sprintf("error opening input file: %v", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(tempOutputFile)
	if err != nil {
		return fmt.Sprintf("error creating temporary output file: %v", err)
	}

	var metadataBuffer bytes.Buffer

binary.Write(&metadataBuffer, binary.BigEndian, uint16(len(hintBytes)))
	metadataBuffer.Write(hintBytes)
	binary.Write(&metadataBuffer, binary.BigEndian, uint16(channel))
	binary.Write(&metadataBuffer, binary.BigEndian, encryptionLevelCode)
	metadataBuffer.Write(aesKeySalt)
	metadataBuffer.Write(hmacKeySalt)
	metadataBuffer.Write(ctrIV)

	_, err = outFile.Write(metadataBuffer.Bytes())
	if err != nil {
		return fmt.Sprintf("error writing metadata to output file: %v", err)
	}

	hmacHasher := hmac.New(sha256.New, hmacKey)
	hmacHasher.Write(metadataBuffer.Bytes())

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Sprintf("error creating AES cipher: %v", err)
	}
	stream := cipher.NewCTR(block, ctrIV)

	multiWriter := io.MultiWriter(outFile, hmacHasher)

	buf := make([]byte, ChunkSize)
	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			encryptedChunk := make([]byte, n)
			stream.XORKeyStream(encryptedChunk, buf[:n])
			_, err = multiWriter.Write(encryptedChunk)
			if err != nil {
				return fmt.Sprintf("error writing encrypted chunk: %v", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Sprintf("error reading input file chunk: %v", err)
		}
	}

	hmacTag := hmacHasher.Sum(nil)
	_, err = outFile.Write(hmacTag)
	if err != nil {
		return fmt.Sprintf("error writing HMAC tag: %v", err)
	}
	outFile.Close()

	verificationResult := a.DecryptFile(tempOutputFile, string(password), true, channel)
	if verificationResult != "success" {
		os.Remove(tempOutputFile)
		return fmt.Sprintf("encryption verification failed: %s", verificationResult)
	}

	time.Sleep(200 * time.Millisecond)

	err = os.Rename(tempOutputFile, outputFile)
	if err != nil {
		return fmt.Sprintf("error renaming temporary file: %v", err)
	}

	os.Remove(inputFile)
	return "success"
}

// DecryptFile decrypts a single .gie file.
func (a *App) DecryptFile(inputFile string, password string, verifyMode bool, expectedChannel int) string {
	passwordBytes := []byte(password)
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Sprintf("error opening file: %v", err)
	}
	defer inFile.Close()

	fileInfo, err := inFile.Stat()
	if err != nil {
		return fmt.Sprintf("error getting file info: %v", err)
	}

	var metadataBuffer bytes.Buffer
	metadataReader := io.TeeReader(inFile, &metadataBuffer)

	var hintLen uint16
	binary.Read(metadataReader, binary.BigEndian, &hintLen)
	hintBytes := make([]byte, hintLen)
	io.ReadFull(metadataReader, hintBytes)

	var fileChannel uint16
	binary.Read(metadataReader, binary.BigEndian, &fileChannel)

	var fileEncryptionLevelCode byte
	binary.Read(metadataReader, binary.BigEndian, &fileEncryptionLevelCode)

	aesKeySalt := make([]byte, 16)
	io.ReadFull(metadataReader, aesKeySalt)
	hmacKeySalt := make([]byte, 16)
	io.ReadFull(metadataReader, hmacKeySalt)
	ctrIV := make([]byte, CTRIVSize)
	io.ReadFull(metadataReader, ctrIV)

	if int(fileChannel) != expectedChannel {
		return "incorrect channel"
	}

	encryptionLevelName, ok := EncryptionLevelCodesReverse[fileEncryptionLevelCode]
	if !ok {
		encryptionLevelName = "Normal"
	}
	levelParams := EncryptionLevels[encryptionLevelName]
	aesKey := DeriveKeyFromPassword(passwordBytes, aesKeySalt, levelParams.Iterations, levelParams.KeyLength)
	hmacKey := DeriveKeyFromPassword(passwordBytes, hmacKeySalt, levelParams.Iterations, levelParams.KeyLength)

	ciphertextStartPos := int64(metadataBuffer.Len())
	ciphertextLength := fileInfo.Size() - ciphertextStartPos - HMACSize

	hmacHasher := hmac.New(sha256.New, hmacKey)
	hmacHasher.Write(metadataBuffer.Bytes())

	// Hash the ciphertext
	teeReader := io.TeeReader(io.LimitReader(inFile, ciphertextLength), hmacHasher)
	io.Copy(io.Discard, teeReader)

	expectedHMAC := make([]byte, HMACSize)
	io.ReadFull(inFile, expectedHMAC)

	if !hmac.Equal(hmacHasher.Sum(nil), expectedHMAC) {
		return "HMAC verification failed: data may be corrupted or password incorrect"
	}

	if verifyMode {
		return "success"
	}

	// Decrypt
	inFile.Seek(ciphertextStartPos, io.SeekStart)
	outputFile := strings.TrimSuffix(inputFile, ".gie")
	if strings.HasSuffix(outputFile, ".tmp") {
		outputFile = strings.TrimSuffix(outputFile, ".tmp")
	}
	tempOutputFile := outputFile + ".tmp.dec"

	out, err := os.Create(tempOutputFile)
	if err != nil {
		return fmt.Sprintf("error creating temporary output file: %v", err)
	}
	defer out.Close()

	block, _ := aes.NewCipher(aesKey)
	stream := cipher.NewCTR(block, ctrIV)
	reader := &cipher.StreamReader{S: stream, R: io.LimitReader(inFile, ciphertextLength)}
	io.Copy(out, reader)

	out.Close()
	inFile.Close()

	err = os.Rename(tempOutputFile, outputFile)
	if err != nil {
		return fmt.Sprintf("error renaming decrypted file: %v", err)
	}

	os.Remove(inputFile)
	return "success"
}

// OpenExternalURL opens a URL in the default browser.
func (a *App) OpenExternalURL(url string) {
	runtime.BrowserOpenURL(a.ctx, url)
}

// SelectDirectory opens a directory dialog to select a directory.
func (a *App) SelectDirectory() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Directory",
	})
}

// IsDirectory checks if the given path is a directory
func (a *App) IsDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// GetFilesInDirectory recursively gets all files in a directory
func (a *App) GetFilesInDirectory(dirPath string) ([]string, error) {
	var files []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !strings.HasSuffix(path, ".gie") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// EncryptDirectory encrypts all files in a directory recursively
func (a *App) EncryptDirectory(dirPath string, password string, hint string, encryptionLevel string, channel int) string {
	files, err := a.GetFilesInDirectory(dirPath)
	if err != nil {
		return fmt.Sprintf("Error getting files from directory: %v", err)
	}
	if len(files) == 0 {
		return "No files found to encrypt."
	}

	var results []string
	successCount := 0
	for _, file := range files {
		result := a.EncryptFile(file, password, hint, encryptionLevel, channel)
		if result == "success" {
			successCount++
		}
		results = append(results, fmt.Sprintf("%s: %s", filepath.Base(file), result))
	}

	return fmt.Sprintf("Directory encryption completed: %d/%d files successful.\n%s", successCount, len(files), strings.Join(results, "\n"))
}

// DecryptDirectory decrypts all .gie files in a directory recursively
func (a *App) DecryptDirectory(dirPath string, password string, channel int) string {
	var encryptedFiles []string
	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(path, ".gie") {
			encryptedFiles = append(encryptedFiles, path)
		}
		return nil
	})

	if len(encryptedFiles) == 0 {
		return "No encrypted files found."
	}

	var results []string
	successCount := 0
	for _, file := range encryptedFiles {
		result := a.DecryptFile(file, password, false, channel)
		if result == "success" {
			successCount++
		}
		results = append(results, fmt.Sprintf("%s: %s", filepath.Base(file), result))
	}

	return fmt.Sprintf("Directory decryption completed: %d/%d files successful.\n%s", successCount, len(encryptedFiles), strings.Join(results, "\n"))
}

// GetHint reads the hint from a .gie file without full decryption.
func (a *App) GetHint(inputFile string) (string, error) {
	if !strings.HasSuffix(strings.ToLower(inputFile), ".gie") {
		return "", nil
	}
	inFile, err := os.Open(inputFile)
	if err != nil {
		return "", fmt.Errorf("error opening file: %v", err)
	}
	defer inFile.Close()

	var hintLen uint16
	err = binary.Read(inFile, binary.BigEndian, &hintLen)
	if err != nil {
		return "", fmt.Errorf("error reading hint length: %v", err)
	}

	const maxHintLength = 4096
	if hintLen > maxHintLength {
		return "", fmt.Errorf("hint length (%d) exceeds maximum allowed size", hintLen)
	}

	if hintLen == 0 {
		return "", nil
	}

	hintBytes := make([]byte, hintLen)
	_, err = io.ReadFull(inFile, hintBytes)
	if err != nil {
		return "", fmt.Errorf("error reading hint: %v", err)
	}

	return string(hintBytes), nil
}

// DeriveKeyFromPassword derives a key from a password and salt using PBKDF2-HMAC-SHA256.
func DeriveKeyFromPassword(password, salt []byte, iterations, keyLength int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLength, sha256.New)
}

// GenerateSalt generates a random salt of the specified length.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateIV generates a random IV of the specified length.
func GenerateIV(length int) ([]byte, error) {
	iv := make([]byte, length)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}