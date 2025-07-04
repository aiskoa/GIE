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
	"regexp"
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
	fmt.Printf("DEBUG: Registering OnFileDrop handler.\n")
	runtime.OnFileDrop(ctx, func(x, y int, paths []string) {
		fmt.Printf("DEBUG: OnFileDrop triggered in Go backend. X: %d, Y: %d, Paths: %v\n", x, y, paths)
		if len(paths) > 0 {
			fmt.Printf("DEBUG: Emitting wails:drag:drop event with paths: %v\n", paths)
			runtime.EventsEmit(ctx, "wails:drag:drop", paths)
		} else {
			fmt.Printf("DEBUG: No paths received in OnFileDrop event.\n")
		}
	})

	// Check if a file path was passed as a command-line argument
	if len(os.Args) > 1 {
		filePath := os.Args[1]
		fmt.Printf("DEBUG: Application launched with argument: %s\n", filePath)

		// You might want to add checks here to ensure it's a .gie file
		if strings.HasSuffix(strings.ToLower(filePath), ".gie") {
			// Emit an event to the frontend to handle the decryption
			// The frontend will then prompt for password and channel
			runtime.EventsEmit(ctx, "wails:open:gie", filePath)
			fmt.Printf("DEBUG: Emitted wails:open:gie event for file: %s\n", filePath)
		} else {
			fmt.Printf("DEBUG: Passed file is not a .gie file: %s\n", filePath)
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
	LargeFileThreshold = 10 * 1024 * 1024 // 10 MB - Force streaming for testing
	ChunkSize          = 1024 * 1024      // 1 MB
	CTRIVSize          = 16               // AES-CTR IV size
	HMACSize           = 32               // SHA256 HMAC size
)

// EncryptionLevel defines parameters for different encryption strengths.
type EncryptionLevel struct {
	Iterations int
	KeyLength  int // in bytes
}

var EncryptionLevels = map[string]EncryptionLevel{
	"Low":    {Iterations: 10000, KeyLength: 16},    // AES-128
	"Normal": {Iterations: 800000, KeyLength: 32},   // AES-256
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

	// Generate salts for AES key and HMAC key
	aesKeySalt, err := GenerateSalt(16)
	if err != nil {
		return fmt.Sprintf("error generating AES key salt: %v", err)
	}
	hmacKeySalt, err := GenerateSalt(16)
	if err != nil {
		return fmt.Sprintf("error generating HMAC key salt: %v", err)
	}

	// Derive AES key and HMAC key
	aesKey := DeriveKeyFromPassword(passwordBytes, aesKeySalt, levelParams.Iterations, levelParams.KeyLength)
	hmacKey := DeriveKeyFromPassword(passwordBytes, hmacKeySalt, levelParams.Iterations, levelParams.KeyLength)

	// Generate CTR IV
	ctrIV, err := GenerateIV(CTRIVSize)
	if err != nil {
		return fmt.Sprintf("error generating CTR IV: %v", err)
	}

	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Sprintf("error opening input file: %v", err)
	}
	defer inFile.Close() // Ensure input file is closed

	// Create temporary output file
	outFile, err := os.Create(tempOutputFile)
	if err != nil {
		return fmt.Sprintf("error creating temporary output file: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			os.Remove(tempOutputFile) // Clean up temp file on panic
			panic(r)
		}
	}()

	// Create a buffer to capture metadata for HMAC calculation
	var metadataBuffer bytes.Buffer

	// Write metadata to metadataBuffer first
	err = binary.Write(&metadataBuffer, binary.BigEndian, uint16(len(hintBytes)))
	if err != nil {
		return fmt.Sprintf("error writing hint length to buffer: %v", err)
	}
	_, err = metadataBuffer.Write(hintBytes)
	if err != nil {
		return fmt.Sprintf("error writing hint to buffer: %v", err)
	}
	err = binary.Write(&metadataBuffer, binary.BigEndian, uint16(channel))
	if err != nil {
		return fmt.Sprintf("error writing channel to buffer: %v", err)
	}
	err = binary.Write(&metadataBuffer, binary.BigEndian, encryptionLevelCode)
	if err != nil {
		return fmt.Sprintf("error writing encryption level code to buffer: %v", err)
	}
	_, err = metadataBuffer.Write(aesKeySalt)
	if err != nil {
		return fmt.Sprintf("error writing AES key salt to buffer: %v", err)
	}
	_, err = metadataBuffer.Write(hmacKeySalt)
	if err != nil {
		return fmt.Sprintf("error writing HMAC key salt to buffer: %v", err)
	}
	_, err = metadataBuffer.Write(ctrIV)
	if err != nil {
		return fmt.Sprintf("error writing CTR IV to buffer: %v", err)
	}

	// Write metadata from buffer to output file
	_, err = outFile.Write(metadataBuffer.Bytes())
	if err != nil {
		return fmt.Sprintf("error writing metadata to output file: %v", err)
	}

	// Initialize HMAC and feed it the metadata
	hmacHasher := hmac.New(sha256.New, hmacKey)
	hmacHasher.Write(metadataBuffer.Bytes()) // Feed metadata to HMAC

	// Initialize AES cipher for CTR mode
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Sprintf("error creating AES cipher: %v", err)
	}
	stream := cipher.NewCTR(block, ctrIV)

	// Create a MultiWriter to write to both outFile and hmacHasher
	// This ensures HMAC is calculated over the ciphertext as it's written
	multiWriter := io.MultiWriter(outFile, hmacHasher)

	// Encrypt and write data in chunks
	buf := make([]byte, ChunkSize)
	for {
		n, err := inFile.Read(buf)
		if n == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return fmt.Sprintf("error reading input file chunk: %v", err)
		}

		encryptedChunk := make([]byte, n)
		stream.XORKeyStream(encryptedChunk, buf[:n])

		_, err = multiWriter.Write(encryptedChunk)
		if err != nil {
			return fmt.Sprintf("error writing encrypted chunk: %v", err)
		}
	}
	inFile.Close() // Explicitly close the input file after reading all its content

	// Finalize HMAC and write the tag
	hmacTag := hmacHasher.Sum(nil)
	_, err = outFile.Write(hmacTag)
	if err != nil {
		return fmt.Sprintf("error writing HMAC tag: %v", err)
	}
	outFile.Sync()  // Force write to disk
	outFile.Close() // Close to ensure all data is flushed before verification

	// Verification Step (decrypt the temporary file and verify HMAC)
	fmt.Printf("DEBUG: Starting verification of %s\n", tempOutputFile)
	verificationResult := a.DecryptFile(tempOutputFile, string(password), true, channel)
	fmt.Printf("DEBUG: Verification of %s finished with result: %s\n", tempOutputFile, verificationResult)
	if verificationResult != "success" {
		os.Remove(tempOutputFile)
		return fmt.Sprintf("encryption verification failed: %s", verificationResult)
	}

	fmt.Printf("DEBUG: Verification successful. Attempting to rename %s to %s\n", tempOutputFile, outputFile)
	// Give the OS a moment to release the file handle before renaming
	time.Sleep(500 * time.Millisecond) // Increased sleep time

	// Retry renaming the temporary file a few times
	maxRetries := 10                     // Increased retries
	retryDelay := 200 * time.Millisecond // Increased retry delay

	for i := 0; i < maxRetries; i++ {
		err = os.Rename(tempOutputFile, outputFile)
		if err == nil {
			fmt.Printf("DEBUG: Successfully renamed %s to %s\n", tempOutputFile, outputFile)
			break // Success, exit loop
		}
		fmt.Printf("DEBUG: Rename attempt %d for %s failed: %v. Retrying...\n", i+1, tempOutputFile, err)
		if i == maxRetries-1 {
			return fmt.Sprintf("error renaming temporary file after multiple retries: %v", err)
		}
		time.Sleep(retryDelay)
	}

	// If rename still failed after retries
	if err != nil {
		os.Remove(tempOutputFile) // Clean up temp file if rename fails
		return fmt.Sprintf("error renaming temporary file: %v", err)
	}

	fmt.Printf("DEBUG: Renaming successful. Attempting to delete original input file %s\n", inputFile)
	// Give the OS a moment to release the file handle before attempting to delete the original
	time.Sleep(100 * time.Millisecond)

	// Attempt to delete the original input file by renaming it first
	fileToDelete := inputFile + ".todelete"
	renErr := os.Rename(inputFile, fileToDelete)
	if renErr != nil {
		fmt.Printf("WARNING: Could not rename original file %s for deletion: %v\n", inputFile, renErr)
	} else {
		maxRetriesRemove := 10
		retryDelayRemove := 200 * time.Millisecond // 200ms

		for i := 0; i < maxRetriesRemove; i++ {
			removeErr := os.Remove(fileToDelete)
			if removeErr == nil {
				break // Success, exit loop
			}
			// If it's the last retry and still an error, print a warning
			if i == maxRetriesRemove-1 {
				fmt.Printf("WARNING: Could not delete original file %s after multiple retries: %v\n", fileToDelete, removeErr)
			}
			time.Sleep(retryDelayRemove)
		}
	}
	return "success"
}

// DecryptFile decrypts a single .gie file using AES-CTR and HMAC-SHA256.
func (a *App) DecryptFile(inputFile string, password string, verifyMode bool, expectedChannel int) string {
	passwordBytes := []byte(password)
	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Sprintf("error opening file: %v", err)
	}
	defer inFile.Close() // Ensure input file is closed

	fileInfo, err := inFile.Stat()
	if err != nil {
		return fmt.Sprintf("error getting file info: %v", err)
	}
	fmt.Printf("DEBUG: DecryptFile - File size: %d bytes\n", fileInfo.Size())

	// Create a buffer to capture metadata for HMAC calculation during decryption
	var metadataBuffer bytes.Buffer
	metadataReader := io.TeeReader(inFile, &metadataBuffer) // Read from inFile, write to metadataBuffer

	// Read metadata using metadataReader
	var hintLen uint16
	err = binary.Read(metadataReader, binary.BigEndian, &hintLen)
	if err != nil {
		return fmt.Sprintf("error reading hint length: %v", err)
	}
	hintBytes := make([]byte, hintLen)
	_, err = io.ReadFull(metadataReader, hintBytes)
	if err != nil {
		return fmt.Sprintf("error reading hint: %v", err)
	}

	var fileChannel uint16
	err = binary.Read(metadataReader, binary.BigEndian, &fileChannel)
	if err != nil {
		return fmt.Sprintf("error reading file channel: %v", err)
	}

	var fileEncryptionLevelCode byte
	err = binary.Read(metadataReader, binary.BigEndian, &fileEncryptionLevelCode)
	if err != nil {
		return fmt.Sprintf("error reading encryption level code: %v", err)
	}

	aesKeySalt := make([]byte, 16)
	_, err = io.ReadFull(metadataReader, aesKeySalt)
	if err != nil {
		return fmt.Sprintf("error reading AES key salt: %v", err)
	}
	hmacKeySalt := make([]byte, 16)
	_, err = io.ReadFull(metadataReader, hmacKeySalt)
	if err != nil {
		return fmt.Sprintf("error reading HMAC key salt: %v", err)
	}
	ctrIV := make([]byte, CTRIVSize)
	_, err = io.ReadFull(metadataReader, ctrIV)
	if err != nil {
		return fmt.Sprintf("error reading CTR IV: %v", err)
	}

	fmt.Printf("DEBUG: DecryptFile - Metadata length: %d bytes\n", metadataBuffer.Len())

	// Verify channel
	if int(fileChannel) != expectedChannel {
		return "incorrect channel. Please ensure you are using the correct channel for this file."
	}

	// Derive keys
	encryptionLevelName, ok := EncryptionLevelCodesReverse[fileEncryptionLevelCode]
	if !ok {
		encryptionLevelName = "Normal"
	}
	levelParams := EncryptionLevels[encryptionLevelName]
	aesKey := DeriveKeyFromPassword(passwordBytes, aesKeySalt, levelParams.Iterations, levelParams.KeyLength)
	hmacKey := DeriveKeyFromPassword(passwordBytes, hmacKeySalt, levelParams.Iterations, levelParams.KeyLength)

	// Calculate the size of the ciphertext (total file size - metadata size - HMAC tag size)
	// metadataBuffer.Len() gives the size of the metadata that was read into the buffer
	ciphertextStartPos := int64(metadataBuffer.Len())
	ciphertextEndPos := fileInfo.Size() - HMACSize
	ciphertextLength := ciphertextEndPos - ciphertextStartPos

	fmt.Printf("DEBUG: DecryptFile - Ciphertext start: %d, end: %d, length: %d\n", ciphertextStartPos, ciphertextEndPos, ciphertextLength)

	// Initialize HMAC and feed it the metadata
	hmacHasher := hmac.New(sha256.New, hmacKey)
	hmacHasher.Write(metadataBuffer.Bytes()) // Feed metadata to HMAC

	// Feed ciphertext to HMAC
	// Create a limited reader for the ciphertext part of the file
	// IMPORTANT: The inFile's current position is already at ciphertextStartPos due to TeeReader.
	// So, we can just use io.LimitReader directly on inFile for HMAC calculation.
	currentPos, _ := inFile.Seek(0, io.SeekCurrent)
	fmt.Printf("DEBUG: DecryptFile - Before HMAC copy, inFile current pos: %d\n", currentPos)

	// Create a buffer to read chunks from the file
	buf := make([]byte, ChunkSize)
	var totalBytesRead int64

	for totalBytesRead < ciphertextLength {
		bytesToRead := ChunkSize
		if remaining := ciphertextLength - totalBytesRead; remaining < int64(ChunkSize) {
			bytesToRead = int(remaining)
		}

		n, err := inFile.Read(buf[:bytesToRead])
		if n == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return fmt.Sprintf("error reading ciphertext chunk for HMAC: %v", err)
		}

		hmacHasher.Write(buf[:n])
		totalBytesRead += int64(n)
	}
	fmt.Printf("DEBUG: DecryptFile - Total bytes fed to HMAC: %d\n", totalBytesRead)

	// Read expected HMAC tag from file
	expectedHMAC := make([]byte, HMACSize)
	// The current position of inFile is now at ciphertextEndPos (after reading ciphertext for HMAC)
	currentPos, _ = inFile.Seek(0, io.SeekCurrent)
	fmt.Printf("DEBUG: DecryptFile - Before reading HMAC tag, inFile current pos: %d\n", currentPos)
	_, err = io.ReadFull(inFile, expectedHMAC)
	if err != nil {
		return fmt.Sprintf("error reading HMAC tag: %v", err)
	}

	// Verify HMAC
	if !hmac.Equal(hmacHasher.Sum(nil), expectedHMAC) {
		return "HMAC verification failed: data may be corrupted or password incorrect"
	}

	// If HMAC is valid, proceed with decryption
	// Seek back to the beginning of the ciphertext for decryption
	// This seek is necessary because io.Copy advanced the inFile's position.
	_, err = inFile.Seek(ciphertextStartPos, io.SeekStart)
	if err != nil {
		return fmt.Sprintf("error seeking to ciphertext for decryption: %v", err)
	}
	currentPos, _ = inFile.Seek(0, io.SeekCurrent)
	fmt.Printf("DEBUG: DecryptFile - After seeking for decryption, inFile current pos: %d\n", currentPos)

	// Initialize AES cipher for CTR mode
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Sprintf("error creating AES cipher: %v", err)
	}
	stream := cipher.NewCTR(block, ctrIV)

	// Decrypt and write data in chunks
	// Use a LimitReader to ensure we only read the ciphertext part
	limitedReader := io.LimitReader(inFile, ciphertextLength)
	reader := &cipher.StreamReader{S: stream, R: limitedReader}

	// If in verifyMode, write to buffer; otherwise, write to file
	if verifyMode {
		// In verify mode, we don't need to store the decrypted data, just read it to verify.
		_, err = io.Copy(io.Discard, reader)
		if err != nil {
			return fmt.Sprintf("error decrypting in verify mode: %v", err)
		}
	} else {
		outputFile := strings.TrimSuffix(inputFile, ".gie")
		// If the input file already had a .tmp suffix (e.g., from a previous failed encryption),
		// remove it to get the true original filename.
		if strings.HasSuffix(outputFile, ".tmp") {
			outputFile = strings.TrimSuffix(outputFile, ".tmp")
		}
		tempOutputFile := outputFile + ".tmp"
		fmt.Printf("DEBUG: DecryptFile creating temporary output file: %s\n", tempOutputFile)
		outFile, err := os.Create(tempOutputFile)
		if err != nil {
			return fmt.Sprintf("error creating temporary output file: %v", err)
		}
		defer outFile.Close()           // Ensure output file is closed
		defer os.Remove(tempOutputFile) // Ensure temp file is cleaned up on error

		// Decrypt and write data in chunks
		buf := make([]byte, ChunkSize)
		for {
			n, err := reader.Read(buf)
			if n == 0 {
				break
			}
			if err != nil && err != io.EOF {
				return fmt.Sprintf("error reading decrypted chunk: %v", err)
			}
			_, err = outFile.Write(buf[:n])
			if err != nil {
				return fmt.Sprintf("error writing decrypted chunk: %v", err)
			}
		}

		outFile.Close() // Close to ensure all data is flushed
		// Close the input file before attempting to delete it
		inFile.Close()
		fmt.Printf("DEBUG: Closed input file %s before deletion attempt.\n", inputFile)

		err = os.Rename(tempOutputFile, outputFile)
		if err != nil {
			return fmt.Sprintf("error renaming temporary file: %v", err)
		}

		// Give the OS a moment to release the file handle before attempting to delete the original
		time.Sleep(100 * time.Millisecond)

		// Attempt to delete the original input file by renaming it first
		fileToDelete := inputFile + ".todelete"
		fmt.Printf("DEBUG: Attempting to rename %s to %s for deletion.\n", inputFile, fileToDelete)
		renErr := os.Rename(inputFile, fileToDelete)
		if renErr != nil {
			fmt.Printf("WARNING: Could not rename original .gie file %s for deletion: %v\n", inputFile, renErr)
		} else {
			maxRetriesRemove := 10
			retryDelayRemove := 200 * time.Millisecond // 200ms
			fmt.Printf("DEBUG: Renamed %s to %s. Attempting to delete.\n", inputFile, fileToDelete)

			for i := 0; i < maxRetriesRemove; i++ {
				removeErr := os.Remove(fileToDelete)
				if removeErr == nil {
					fmt.Printf("DEBUG: Successfully deleted original .gie file: %s\n", fileToDelete)
					break // Success, exit loop
				}
				fmt.Printf("DEBUG: Deletion attempt %d for %s failed: %v. Retrying...\n", i+1, fileToDelete, removeErr)
				time.Sleep(retryDelayRemove)
			}
		}
	}

	return "success"
}

// Agregar estas funciones al final de app.go, antes de las funciones de utilidad existentes

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

		// Skip directories, only add files
		if !info.IsDir() {
			// Skip already encrypted files
			if !strings.HasSuffix(path, ".gie") {
				files = append(files, path)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// EncryptDirectory encrypts all files in a directory recursively
func (a *App) EncryptDirectory(dirPath string, password string, hint string, encryptionLevel string, channel int) string {
	if password == "" {
		return "Encryption failed: password cannot be empty."
	}

	// Check if path is actually a directory
	isDir, err := a.IsDirectory(dirPath)
	if err != nil {
		return fmt.Sprintf("Error checking if path is directory: %v", err)
	}
	if !isDir {
		return "Selected path is not a directory."
	}

	// Get all files in directory
	files, err := a.GetFilesInDirectory(dirPath)
	if err != nil {
		return fmt.Sprintf("Error getting files from directory: %v", err)
	}

	if len(files) == 0 {
		return "No files found in directory to encrypt."
	}

	// Track results
	var results []string
	successCount := 0

	for i, file := range files {
		fmt.Printf("Encrypting file %d/%d: %s\n", i+1, len(files), file)

		result := a.EncryptFile(file, password, hint, encryptionLevel, channel)
		if result == "success" {
			successCount++
			results = append(results, fmt.Sprintf("✓ %s", filepath.Base(file)))
		} else {
			results = append(results, fmt.Sprintf("✗ %s: %s", filepath.Base(file), result))
		}
	}

	// Return summary
	summary := fmt.Sprintf("Directory encryption completed: %d/%d files encrypted successfully", successCount, len(files))
	if successCount < len(files) {
		summary += "\n\nDetailed results:\n" + strings.Join(results, "\n")
	}

	return summary
}

// DecryptDirectory decrypts all .gie files in a directory recursively
func (a *App) DecryptDirectory(dirPath string, password string, channel int) string {
	if password == "" {
		return "Decryption failed: password cannot be empty."
	}

	// Check if path is actually a directory
	isDir, err := a.IsDirectory(dirPath)
	if err != nil {
		return fmt.Sprintf("Error checking if path is directory: %v", err)
	}
	if !isDir {
		return "Selected path is not a directory."
	}

	// Get all .gie files in directory
	var encryptedFiles []string

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only add .gie files
		if !info.IsDir() && strings.HasSuffix(path, ".gie") {
			encryptedFiles = append(encryptedFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Sprintf("Error scanning directory: %v", err)
	}

	if len(encryptedFiles) == 0 {
		return "No encrypted files (.gie) found in directory to decrypt."
	}

	// Track results
	var results []string
	successCount := 0

	for i, file := range encryptedFiles {
		fmt.Printf("Decrypting file %d/%d: %s\n", i+1, len(encryptedFiles), file)

		result := a.DecryptFile(file, password, false, channel)
		if result == "success" {
			successCount++
			results = append(results, fmt.Sprintf("✓ %s", filepath.Base(file)))
		} else {
			results = append(results, fmt.Sprintf("✗ %s: %s", filepath.Base(file), result))
		}
	}

	// Return summary
	summary := fmt.Sprintf("Directory decryption completed: %d/%d files decrypted successfully", successCount, len(encryptedFiles))
	if successCount < len(encryptedFiles) {
		summary += "\n\nDetailed results:\n" + strings.Join(results, "\n")
	}

	return summary
}

// GetHint reads the hint from a .gie file without full decryption.
func (a *App) GetHint(inputFile string) (string, error) {
	// Only try to read hints from .gie files
	if !strings.HasSuffix(strings.ToLower(inputFile), ".gie") {
		return "", nil // Not a gie file, no hint to read
	}

	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return "", fmt.Errorf("error opening file: %v", err)
	}
	defer inFile.Close()

	// Read hint length (uint16, 2 bytes)
	var hintLen uint16
	err = binary.Read(inFile, binary.BigEndian, &hintLen)
	if err != nil {
		// If we can't even read the length, it's probably not a valid .gie file or is corrupted
		return "", fmt.Errorf("error reading hint length: %v", err)
	}

	// Basic sanity check for hint length to avoid allocating huge memory for a corrupted file
	const maxHintLength = 4096 // 4KB, a reasonable limit for a hint
	if hintLen > maxHintLength {
		return "", fmt.Errorf("hint length (%d) exceeds maximum allowed size", hintLen)
	}
    
    if hintLen == 0 {
        return "", nil // No hint present
    }

	// Read the hint itself
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

// IsPasswordValid checks if the password contains only allowed characters.
func IsPasswordValid(password string) bool {
	allowedCharsPattern := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_\-+=<>?,.:;{}\[\]|~` + "`" + `]*$`)
	return allowedCharsPattern.MatchString(password)
}

// IsPathValid checks if a file path is valid.
func IsPathValid(path string) (bool, string) {
	// Check path length (Windows has a default limit of 260 chars)
	if len(path) > 259 {
		return false, "The path is too long (max 259 characters)."
	}

	// Extract the base name of the file/directory
	baseName := filepath.Base(path)

	// Check for invalid characters in the base name.
	// This regex checks for characters that are generally problematic in file names.
	invalidCharPattern := regexp.MustCompile(`[<>:\"/\\|\?\*\x00-\x1F]`)
	if invalidCharPattern.MatchString(baseName) {
		return false, "The file name contains invalid characters (e.g., <, >, :, \"/, \\, |, ?, *) or non-ASCII characters like emojis."
	}

	return true, ""
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
