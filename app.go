// app.go: The main application file.
// /internal/: config, crypto, file, operation files
// --------------------------------------------------------------------
//
// Copyright (C) 2025  Aiskoa <aiskoa@mail.com>
// --------------------------------------------------------------------
// Author: Aiskoa
// Language: Go
// Last update: 2025-08-15
// Time: 19:44
// Email: aiskoa@mail.com
// Web: https://github.com/aiskoa/GIE
// Description: File Encryption
// License: https://github.com/aiskoa/GIE/blob/main/LICENSE
// --------------------------------------------------------------------
//

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"

	"gie/internal/config"
	"gie/internal/crypto"
	"gie/internal/file"
	"gie/internal/logging"
	"gie/internal/operation"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx              context.Context
	settings         *config.Settings
	currentOperation *operation.Operation
	operationMutex   sync.RWMutex
	// Add a counter to track decrypt attempts for debugging
	decryptAttempts map[string]int
	attemptsMutex   sync.RWMutex
}

// ProgressCallback represents a progress update
type ProgressCallback struct {
	BytesProcessed int64
	TotalBytes     int64
	Percentage     float64
	Stage          string
}

func NewApp() *App {
	settings, _ := config.LoadSettings()

	// Initialize logging system
	if err := logging.InitLogger(); err != nil {
		fmt.Printf("Warning: Failed to initialize logging: %v\n", err)
	}

	return &App{
		settings:        settings,
		decryptAttempts: make(map[string]int),
	}
}

func (a *App) OnStartup(ctx context.Context) {
	a.ctx = ctx
	logging.LogInfo("Application started")
}

func (a *App) OnDomReady(ctx context.Context) {
	// Here you can call the frontend
}

// OnBeforeClose is called when the application is about to quit,
// either by clicking the window close button or calling runtime.Quit.
// Returning true will cause the application to continue, false will continue shutdown as normal.
func (a *App) OnBeforeClose(ctx context.Context) (prevent bool) {
	return false
}

func (a *App) OnShutdown(ctx context.Context) {
	logging.LogInfo("Application shutting down")
}

func (a *App) GetSettings() *config.Settings {
	return a.settings
}

func (a *App) UpdateSettings(settings *config.Settings) error {
	a.settings = settings
	return config.SaveSettings(settings)
}

func (a *App) IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// FileMetadata represents metadata from an encrypted file
type FileMetadata struct {
	Hint            string `json:"hint"`
	EncryptionLevel string `json:"encryptionLevel"`
	Channel         int    `json:"channel"`
	Method          string `json:"method"`
	OriginalExt     string `json:"originalExt"`
}

// GetFileMetadata returns complete metadata from an encrypted file
func (a *App) GetFileMetadata(inputFile string) *FileMetadata {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return nil
	}
	defer inFile.Close()

	// Read hint
	var hintLen uint16
	err = binary.Read(inFile, binary.BigEndian, &hintLen)
	if err != nil {
		return nil
	}

	var hint string
	if hintLen > 0 {
		hintBytes := make([]byte, hintLen)
		_, err = inFile.Read(hintBytes)
		if err != nil {
			return nil
		}
		hint = string(hintBytes)
	}

	var methodCode byte
	err = binary.Read(inFile, binary.BigEndian, &methodCode)
	if err != nil {
		return nil
	}

	var channel uint16
	err = binary.Read(inFile, binary.BigEndian, &channel)
	if err != nil {
		return nil
	}

	var levelCode byte
	err = binary.Read(inFile, binary.BigEndian, &levelCode)
	if err != nil {
		return nil
	}

	var originalExt string
	var originalExtLen uint16
	err = binary.Read(inFile, binary.BigEndian, &originalExtLen)
	if err == nil && originalExtLen > 0 {
		originalExtBytes := make([]byte, originalExtLen)
		_, err = inFile.Read(originalExtBytes)
		if err == nil {
			originalExt = string(originalExtBytes)
		}
	}

	method := crypto.GetMethodFromCode(methodCode)
	levelName := crypto.EncryptionLevelCodesReverse[levelCode]
	if levelName == "" {
		levelName = "Normal"
	}

	return &FileMetadata{
		Hint:            hint,
		EncryptionLevel: levelName,
		Channel:         int(channel),
		Method:          string(method),
		OriginalExt:     originalExt,
	}
}

func (a *App) GetHint(inputFile string) string {
	metadata := a.GetFileMetadata(inputFile)
	if metadata == nil {
		return ""
	}
	return metadata.Hint
}

func (a *App) emitProgress(bytesProcessed, totalBytes int64, stage string) {
	percentage := float64(bytesProcessed) / float64(totalBytes) * 100
	if percentage > 100 {
		percentage = 100
	}

	progress := ProgressCallback{
		BytesProcessed: bytesProcessed,
		TotalBytes:     totalBytes,
		Percentage:     percentage,
		Stage:          stage,
	}

	runtime.EventsEmit(a.ctx, "encryption:progress", progress)
}

const (
	ChunkSize = 1024 * 1024 // 1MB chunks
)

func (a *App) EncryptFile(inputFile string, password string, hint string, encryptionLevel string, channel int, encryptionMethod string, deleteOriginal bool) string {
	logging.LogInfo("EncryptFile called with method: '%s'", encryptionMethod)
	return a.encryptFileInternal(inputFile, password, hint, encryptionLevel, channel, encryptionMethod, deleteOriginal, true)
}

// encryptFileInternal handles the actual encryption with option to show notifications
func (a *App) encryptFileInternal(inputFile string, password string, hint string, encryptionLevel string, channel int, encryptionMethod string, deleteOriginal bool, showNotifications bool) string {
	a.operationMutex.Lock()
	if a.currentOperation != nil {
		a.currentOperation.Cancel()
	}
	a.currentOperation = operation.NewOperation()
	a.operationMutex.Unlock()

	defer func() {
		a.operationMutex.Lock()
		a.currentOperation = nil
		a.operationMutex.Unlock()
	}()

	logging.LogInfo("Starting encryption of: %s", inputFile)

	if password == "" {
		return "Encryption failed: password cannot be empty."
	}

	fileInfo, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Sprintf("error getting file info: %v", err)
	}
	totalSize := fileInfo.Size()

	method := crypto.EncryptionMethod(encryptionMethod)

	level := crypto.EncryptionLevels[encryptionLevel]
	if encryptionLevel == "" {
		level = crypto.EncryptionLevels["Normal"]
	}

	passwordBytes := []byte(password)
	methodCode := crypto.GetMethodCode(method)

	baseFileName := strings.TrimSuffix(filepath.Base(inputFile), filepath.Ext(inputFile))
	outputDir := filepath.Dir(inputFile)
	outputFile := filepath.Join(outputDir, baseFileName+".gie")

	aesKeySalt, err := crypto.GenerateSalt(32)
	if err != nil {
		return fmt.Sprintf("error generating AES key salt: %v", err)
	}

	hmacKeySalt, err := crypto.GenerateSalt(32)
	if err != nil {
		return fmt.Sprintf("error generating HMAC key salt: %v", err)
	}

	aesKey, hmacKey := crypto.DeriveKeys(passwordBytes, aesKeySalt, hmacKeySalt, level)

	var ivSize int
	switch method {
	case crypto.AES_CTR:
		ivSize = 16 // AES-CTR IV size
	case crypto.CHACHA20:
		ivSize = 12 // ChaCha20 nonce size
	default:
		ivSize = 16 // Default to AES-CTR
	}

	logging.LogInfo("=== ENCRYPTION KEY DERIVATION ===")
	logging.LogInfo("Encryption Method: %s", string(method))
	logging.LogInfo("Password: '%s' (length: %d)", password, len(password))
	logging.LogInfo("Password bytes: %x", passwordBytes)
	logging.LogInfo("Level: %s (iterations: %d)", encryptionLevel, level.Iterations)
	logging.LogInfo("Channel: %d", channel)
	logging.LogInfo("Cipher key salt (full): %x", aesKeySalt)
	logging.LogInfo("HMAC salt (full): %x", hmacKeySalt)
	logging.LogInfo("Derived cipher key (full): %x", aesKey)
	logging.LogInfo("Derived HMAC key (full): %x", hmacKey)
	logging.LogInfo("IV/Nonce size: %d bytes", ivSize)

	iv, err := crypto.GenerateIV(ivSize)
	if err != nil {
		return fmt.Sprintf("error generating IV: %v", err)
	}

	encryptor, err := crypto.CreateEncryptor(method, aesKey, iv)
	if err != nil {
		return fmt.Sprintf("error creating encryptor: %v", err)
	}

	// Open input file and get size for progress tracking
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Sprintf("error opening input file: %v", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Sprintf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Get original file extension ...
	originalExt := filepath.Ext(inputFile)
	originalExtBytes := []byte(originalExt)
	originalExtLen := uint16(len(originalExtBytes))

	// Prepare metadata
	var metadataBuffer bytes.Buffer
	hintBytes := []byte(hint)
	hintLen := uint16(len(hintBytes))

	levelCode := crypto.EncryptionLevelCodes[encryptionLevel]
	if encryptionLevel == "" {
		levelCode = crypto.EncryptionLevelCodes["Normal"]
	}

	binary.Write(&metadataBuffer, binary.BigEndian, hintLen)
	metadataBuffer.Write(hintBytes)
	metadataBuffer.Write([]byte{methodCode})
	binary.Write(&metadataBuffer, binary.BigEndian, uint16(channel))
	metadataBuffer.Write([]byte{levelCode})
	binary.Write(&metadataBuffer, binary.BigEndian, originalExtLen)
	metadataBuffer.Write(originalExtBytes)
	metadataBuffer.Write(aesKeySalt)
	metadataBuffer.Write(hmacKeySalt)
	metadataBuffer.Write(iv)

	logging.LogInfo("Original extension saved: '%s'", originalExt)

	_, err = outFile.Write(metadataBuffer.Bytes())
	if err != nil {
		return fmt.Sprintf("error writing metadata: %v", err)
	}

	hmacHasher := hmac.New(sha256.New, hmacKey)
	hmacHasher.Write(metadataBuffer.Bytes())

	multiWriter := io.MultiWriter(outFile, hmacHasher)

	// Encrypt data in chunks
	buf := make([]byte, ChunkSize)
	var bytesProcessed int64 = 0

	for {
		// Check for cancellation before processing each chunk
		a.operationMutex.RLock()
		if a.currentOperation != nil && a.currentOperation.IsCancelled() {
			a.operationMutex.RUnlock()
			logging.LogInfo("Encryption cancelled by user for: %s", inputFile)

			// Clean up output file
			outFile.Close()
			if err := file.SecureDelete(outputFile); err != nil {
				logging.LogWarning("Failed to securely delete output file after cancellation: %v", err)
			}

			return "Operation cancelled by user"
		}
		a.operationMutex.RUnlock()

		n, err := inFile.Read(buf)
		if n == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return fmt.Sprintf("error reading input file: %v", err)
		}

		// Emit progress before encryption
		a.emitProgress(bytesProcessed, totalSize, "Encrypting...")

		encryptedChunk, err := encryptor.Encrypt(buf[:n])
		if err != nil {
			return fmt.Sprintf("error encrypting chunk: %v", err)
		}

		_, err = multiWriter.Write(encryptedChunk)
		if err != nil {
			return fmt.Sprintf("error writing encrypted chunk: %v", err)
		}

		bytesProcessed += int64(n)

		// Emit progress after encryption
		a.emitProgress(bytesProcessed, totalSize, "Encrypting...")
	}

	// Write HMAC
	hmacSum := hmacHasher.Sum(nil)
	_, err = outFile.Write(hmacSum)
	if err != nil {
		return fmt.Sprintf("error writing HMAC: %v", err)
	}

	// Close files
	inFile.Close()
	outFile.Close()

	// Delete original file if requested
	if deleteOriginal {
		if err := file.SecureDelete(inputFile); err != nil {
			logging.LogWarning("Failed to securely delete original file: %v", err)
			return fmt.Sprintf("Encryption completed, but failed to delete original file: %v", err)
		}
		logging.LogInfo("Original file securely deleted: %s", inputFile)
	}

	logging.LogInfo("Encryption completed successfully: %s", outputFile)

	// Show success notification only if requested
	if showNotifications {
		fileName := filepath.Base(strings.TrimSuffix(outputFile, ".gie"))
		runtime.EventsEmit(a.ctx, "notification", map[string]interface{}{
			"type":     "success",
			"title":    "Encryption Completed",
			"message":  fmt.Sprintf("File '%s' has been encrypted successfully", fileName),
			"duration": 5000,
		})
	}

	// Only restore the level to default, keep the user's channel for convenience
	if a.settings != nil {
		currentTheme := a.settings.Theme
		currentChannel := a.settings.LastUsedChannel // Keep user's channel
		a.settings.LastUsedLevel = "Normal"          // Reset level to default
		a.settings.Theme = currentTheme

		logging.LogInfo("Settings partially restored - Channel: %d (kept), Level: Normal (reset), Theme: %s",
			currentChannel, currentTheme)

		config.SaveSettings(a.settings)
	}

	return "success"
}

func (a *App) DecryptFile(inputFile string, password string, verifyMode bool) string {
	return a.decryptFileInternal(inputFile, password, verifyMode, true)
}

// decryptFileInternal handles the actual decryption with option to show notifications
func (a *App) decryptFileInternal(inputFile string, password string, verifyMode bool, showNotifications bool) string {
	// Auto-detect only the encryption level (channel remains as user's second password)
	if !verifyMode {
		metadata := a.GetFileMetadata(inputFile)
		if metadata != nil {
			// Only update the encryption level automatically, keep user's channel
			currentChannel := a.settings.LastUsedChannel
			a.UpdateChannelAndLevel(currentChannel, metadata.EncryptionLevel)
			logging.LogInfo("Auto-detected encryption level: %s (user channel: %d)", metadata.EncryptionLevel, currentChannel)
		}
	}
	// Create cancellable operation (only for non-verify mode)
	if !verifyMode {
		a.operationMutex.Lock()
		if a.currentOperation != nil {
			a.currentOperation.Cancel()
		}
		a.currentOperation = operation.NewOperation()
		a.operationMutex.Unlock()

		defer func() {
			a.operationMutex.Lock()
			a.currentOperation = nil
			a.operationMutex.Unlock()
		}()
	}

	logging.LogInfo("Starting decryption of: %s", inputFile)

	if password == "" {
		return "Decryption failed: password cannot be empty."
	}

	fileInfo, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Sprintf("error getting file info: %v", err)
	}
	totalSize := fileInfo.Size()

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Sprintf("error opening input file: %v", err)
	}
	defer inFile.Close()

	// Ensure we start from the beginning of the file
	_, err = inFile.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Sprintf("error seeking to start of file: %v", err)
	}

	var metadataBuffer bytes.Buffer
	metadataReader := io.TeeReader(inFile, &metadataBuffer)

	var hintLen uint16
	err = binary.Read(metadataReader, binary.BigEndian, &hintLen)
	if err != nil {
		return fmt.Sprintf("error reading hint length: %v", err)
	}

	hintBytes := make([]byte, hintLen)
	_, err = metadataReader.Read(hintBytes)
	if err != nil {
		return fmt.Sprintf("error reading hint: %v", err)
	}

	var methodCode byte
	err = binary.Read(metadataReader, binary.BigEndian, &methodCode)
	if err != nil {
		return fmt.Sprintf("error reading method code: %v", err)
	}

	// Read channel as uint16
	var channel uint16
	err = binary.Read(metadataReader, binary.BigEndian, &channel)
	if err != nil {
		return fmt.Sprintf("error reading channel: %v", err)
	}

	var levelCode byte
	err = binary.Read(metadataReader, binary.BigEndian, &levelCode)
	if err != nil {
		return fmt.Sprintf("error reading encryption level: %v", err)
	}

	// Read original file extension
	var originalExtLen uint16
	err = binary.Read(metadataReader, binary.BigEndian, &originalExtLen)
	if err != nil {
		return fmt.Sprintf("error reading original extension length: %v", err)
	}

	var originalExt string
	if originalExtLen > 0 {
		originalExtBytes := make([]byte, originalExtLen)
		_, err = metadataReader.Read(originalExtBytes)
		if err != nil {
			return fmt.Sprintf("error reading original extension: %v", err)
		}
		originalExt = string(originalExtBytes)
	}

	logging.LogInfo("Read metadata - Channel: %d, Level: %d, Original extension: '%s'", channel, levelCode, originalExt)

	aesKeySalt := make([]byte, 32)
	_, err = metadataReader.Read(aesKeySalt)
	if err != nil {
		return fmt.Sprintf("error reading AES key salt: %v", err)
	}

	hmacKeySalt := make([]byte, 32)
	_, err = metadataReader.Read(hmacKeySalt)
	if err != nil {
		return fmt.Sprintf("error reading HMAC key salt: %v", err)
	}

	// Determine IV size based on method
	method := crypto.GetMethodFromCode(methodCode)
	var ivSize int
	switch method {
	case crypto.AES_CTR:
		ivSize = 16 // AES-CTR IV size
	case crypto.CHACHA20:
		ivSize = 12 // ChaCha20 nonce size
	default:
		ivSize = 16 // Default to AES-CTR
	}

	iv := make([]byte, ivSize)
	_, err = metadataReader.Read(iv)
	if err != nil {
		return fmt.Sprintf("error reading IV: %v", err)
	}

	// Validate channel - the file's channel must match the user's current channel setting
	logging.LogInfo("Channel validation - File channel: %d, User channel: %d", int(channel), a.settings.LastUsedChannel)

	if int(channel) != a.settings.LastUsedChannel {
		logging.LogInfo("Channel mismatch detected - rejecting decryption")

		// Show error notification for incorrect channel only if requested
		if showNotifications {
			fileName := filepath.Base(inputFile)
			runtime.EventsEmit(a.ctx, "notification", map[string]interface{}{
				"type":     "error",
				"title":    "Decryption Failed",
				"message":  fmt.Sprintf("Incorrect channel for file '%s'. Please check your channel setting.", fileName),
				"duration": 8000,
			})
		}

		// Clear decrypt attempts counter on failure
		a.attemptsMutex.Lock()
		delete(a.decryptAttempts, inputFile)
		a.attemptsMutex.Unlock()
		return "Invalid password or channel."
	}

	logging.LogInfo("Channel validation passed - proceeding with decryption")

	// Calculate ciphertext start position and length
	metadataSize := int64(metadataBuffer.Len())
	hmacSize := int64(32) // SHA-256 HMAC size
	ciphertextLength := totalSize - metadataSize - hmacSize
	ciphertextStartPos := metadataSize

	// Derive keys using the encryption level from file metadata
	passwordBytes := []byte(password)
	levelName := crypto.EncryptionLevelCodesReverse[levelCode]
	if levelName == "" {
		levelName = "Normal"
	}
	level := crypto.EncryptionLevels[levelName]

	logging.LogInfo("=== KEY DERIVATION DEBUG ===")
	logging.LogInfo("Decryption Method: %s", string(method))
	logging.LogInfo("Password: '%s' (length: %d)", password, len(password))
	logging.LogInfo("Password bytes: %x", passwordBytes)
	logging.LogInfo("Level code from file: %d", levelCode)
	logging.LogInfo("Level name: %s", levelName)
	logging.LogInfo("Level iterations: %d", level.Iterations)
	logging.LogInfo("Cipher key salt (full): %x", aesKeySalt)
	logging.LogInfo("HMAC salt (full): %x", hmacKeySalt)
	logging.LogInfo("IV/Nonce size: %d bytes", ivSize)

	aesKey, hmacKey := crypto.DeriveKeys(passwordBytes, aesKeySalt, hmacKeySalt, level)

	logging.LogInfo("Derived cipher key (full): %x", aesKey)
	logging.LogInfo("Derived HMAC key (full): %x", hmacKey)

	// Initialize HMAC and feed it the metadata
	hmacHasher := hmac.New(sha256.New, hmacKey)
	hmacHasher.Write(metadataBuffer.Bytes())

	// Read and verify HMAC
	hmacPos := ciphertextStartPos + ciphertextLength
	_, err = inFile.Seek(hmacPos, io.SeekStart)
	if err != nil {
		return fmt.Sprintf("error seeking to HMAC: %v", err)
	}

	storedHmac := make([]byte, 32)
	_, err = inFile.Read(storedHmac)
	if err != nil {
		return fmt.Sprintf("error reading stored HMAC: %v", err)
	}

	// Read ciphertext for HMAC verification
	_, err = inFile.Seek(ciphertextStartPos, io.SeekStart)
	if err != nil {
		return fmt.Sprintf("error seeking to ciphertext for HMAC verification: %v", err)
	}

	hmacBuffer := make([]byte, 8192)
	var hmacBytesRead int64 = 0
	for hmacBytesRead < ciphertextLength {
		toRead := int64(len(hmacBuffer))
		if hmacBytesRead+toRead > ciphertextLength {
			toRead = ciphertextLength - hmacBytesRead
		}

		n, err := inFile.Read(hmacBuffer[:toRead])
		if err != nil && err != io.EOF {
			return fmt.Sprintf("error reading ciphertext for HMAC: %v", err)
		}
		if n == 0 {
			break
		}

		hmacHasher.Write(hmacBuffer[:n])
		hmacBytesRead += int64(n)
	}

	computedHmac := hmacHasher.Sum(nil)

	logging.LogInfo("=== HMAC VERIFICATION DEBUG ===")
	logging.LogInfo("Stored HMAC: %x", storedHmac[:16])
	logging.LogInfo("Computed HMAC: %x", computedHmac[:16])
	logging.LogInfo("HMAC match: %v", hmac.Equal(storedHmac, computedHmac))
	logging.LogInfo("Metadata size: %d bytes", metadataBuffer.Len())
	logging.LogInfo("Ciphertext length: %d bytes", ciphertextLength)

	if !hmac.Equal(storedHmac, computedHmac) {
		logging.LogInfo("=== HMAC MISMATCH - DECRYPTION FAILED ===")

		// Show error notification for incorrect password only if requested
		if showNotifications {
			fileName := filepath.Base(inputFile)
			runtime.EventsEmit(a.ctx, "notification", map[string]interface{}{
				"type":     "error",
				"title":    "Decryption Failed",
				"message":  fmt.Sprintf("Incorrect password for file '%s'. Please check your password.", fileName),
				"duration": 8000,
			})
		}

		return "Invalid password or channel."
	}

	logging.LogInfo("=== HMAC VERIFIED - PROCEEDING WITH DECRYPTION ===")

	// If this is just verification mode, return success
	if verifyMode {
		return "success"
	}

	// Proceed with decryption
	_, err = inFile.Seek(ciphertextStartPos, io.SeekStart)
	if err != nil {
		return fmt.Sprintf("error seeking to ciphertext for decryption: %v", err)
	}

	// Create a fresh decryptor for each operation to avoid state issues
	decryptor, err := crypto.CreateEncryptor(method, aesKey, iv)
	if err != nil {
		return fmt.Sprintf("error creating decryptor: %v", err)
	}

	// Prepare output file with original extension restored
	baseOutputFile := strings.TrimSuffix(inputFile, ".gie")
	if strings.HasSuffix(baseOutputFile, ".tmp") {
		baseOutputFile = strings.TrimSuffix(baseOutputFile, ".tmp")
	}

	var finalOutputFile string

	// Restore original extension if available
	if originalExt != "" {
		// Remove any existing extension and add the original one
		baseWithoutExt := strings.TrimSuffix(baseOutputFile, filepath.Ext(baseOutputFile))
		finalOutputFile = baseWithoutExt + originalExt

		logging.LogInfo("Restoring original extension: %s -> %s", baseOutputFile, finalOutputFile)
	} else {
		// No original extension saved, use base name
		finalOutputFile = baseOutputFile
		logging.LogInfo("No original extension found, using: %s", finalOutputFile)
	}

	// Handle file conflicts
	counter := 1
	originalFinalOutputFile := finalOutputFile
	for {
		if _, err := os.Stat(finalOutputFile); os.IsNotExist(err) {
			break
		}
		ext := filepath.Ext(originalFinalOutputFile)
		nameWithoutExt := strings.TrimSuffix(originalFinalOutputFile, ext)
		finalOutputFile = fmt.Sprintf("%s (%d)%s", nameWithoutExt, counter, ext)
		counter++
	}

	tempOutputFile := finalOutputFile + ".tmp"
	outFile, err := os.Create(tempOutputFile)
	if err != nil {
		return fmt.Sprintf("error creating output file: %v", err)
	}
	defer outFile.Close()

	limitedReader := io.LimitReader(inFile, ciphertextLength)
	var bytesProcessed int64 = 0

	buf := make([]byte, ChunkSize)
	for {
		// Check for cancellation before processing each chunk (only for non-verify mode)
		if !verifyMode {
			a.operationMutex.RLock()
			if a.currentOperation != nil && a.currentOperation.IsCancelled() {
				a.operationMutex.RUnlock()
				logging.LogInfo("Decryption cancelled by user for: %s", inputFile)

				// Clean up temporary files
				outFile.Close()
				if err := file.SecureDelete(tempOutputFile); err != nil {
					logging.LogWarning("Failed to securely delete temp file after cancellation: %v", err)
				}

				return "Operation cancelled by user"
			}
			a.operationMutex.RUnlock()
		}

		n, err := limitedReader.Read(buf)
		if n == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return fmt.Sprintf("error reading encrypted chunk: %v", err)
		}

		// Emit progress before decryption
		if !verifyMode {
			a.emitProgress(bytesProcessed, ciphertextLength, "Decrypting...")
		}

		decryptedChunk, err := decryptor.Decrypt(buf[:n])
		if err != nil {
			return fmt.Sprintf("error decrypting chunk: %v", err)
		}

		_, err = outFile.Write(decryptedChunk)
		if err != nil {
			return fmt.Sprintf("error writing decrypted chunk: %v", err)
		}

		bytesProcessed += int64(n)

		// Emit progress after processing chunk
		if !verifyMode {
			a.emitProgress(bytesProcessed, ciphertextLength, "Decrypting...")
		}
	}

	outFile.Close()
	inFile.Close()

	// Rename temp file to final name
	err = os.Rename(tempOutputFile, finalOutputFile)
	if err != nil {
		return fmt.Sprintf("error finalizing output file: %v", err)
	}

	// Mark encrypted file for deletion
	deleteFile := inputFile + ".todelete"
	err = os.Rename(inputFile, deleteFile)
	if err != nil {
		logging.LogWarning("Failed to mark encrypted file for deletion: %v", err)
	} else {
		// Delete the marked file
		if err := file.SecureDelete(deleteFile); err != nil {
			logging.LogWarning("Failed to securely delete encrypted file: %v", err)
		}
	}

	// Clear decrypt attempts counter on success
	a.attemptsMutex.Lock()
	delete(a.decryptAttempts, inputFile)
	a.attemptsMutex.Unlock()

	logging.LogInfo("Decryption completed successfully: %s", finalOutputFile)

	// Show success notification only if requested
	if showNotifications {
		fileName := filepath.Base(finalOutputFile)
		runtime.EventsEmit(a.ctx, "notification", map[string]interface{}{
			"type":     "success",
			"title":    "Decryption Completed",
			"message":  fmt.Sprintf("File '%s' has been decrypted successfully", fileName),
			"duration": 5000,
		})
	}

	// Note: Do not restore settings after decryption - user needs to manually set channel <-- ()
	// a.RestoreDefaultSettings() <-- This make me sick

	return "success"
}

// CancelOperation cancels the current operation
func (a *App) CancelOperation() {
	a.operationMutex.Lock()
	defer a.operationMutex.Unlock()

	if a.currentOperation != nil {
		a.currentOperation.Cancel()
		logging.LogInfo("Operation cancelled by user")

		// Emit cancellation event to frontend
		runtime.EventsEmit(a.ctx, "operation:cancelled", map[string]interface{}{
			"message": "Operation cancelled by user",
		})

		// Show cancellation notification
		runtime.EventsEmit(a.ctx, "notification", map[string]interface{}{
			"type":     "info",
			"title":    "Operation Cancelled",
			"message":  "The current operation has been cancelled",
			"duration": 3000,
		})
	}
}

// GetAvailableEncryptionMethods returns the list of available encryption methods
func (a *App) GetAvailableEncryptionMethods() []string {
	return []string{
		string(crypto.AES_CTR),
		string(crypto.CHACHA20),
	}
}

// SelectFile opens a file dialog to select a file
func (a *App) SelectFile() (string, error) {
	selection, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select File",
		Filters: []runtime.FileFilter{
			{
				DisplayName: "All Files",
				Pattern:     "*.*",
			},
			{
				DisplayName: "Encrypted Files (*.gie)",
				Pattern:     "*.gie",
			},
		},
	})

	if err != nil {
		return "", err
	}

	return selection, nil
}

// SelectDirectory opens a directory dialog to select a directory
func (a *App) SelectDirectory() (string, error) {
	selection, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Directory",
	})

	if err != nil {
		return "", err
	}

	return selection, nil
}

// EncryptDirectory encrypts all files in a directory
func (a *App) EncryptDirectory(inputDir string, password string, hint string, encryptionLevel string, channel int, encryptionMethod string, deleteOriginal bool) string {
	// Create cancellable operation
	a.operationMutex.Lock()
	if a.currentOperation != nil {
		a.currentOperation.Cancel()
	}
	a.currentOperation = operation.NewOperation()
	a.operationMutex.Unlock()

	defer func() {
		a.operationMutex.Lock()
		a.currentOperation = nil
		a.operationMutex.Unlock()
	}()

	logging.LogInfo("Starting directory encryption: %s", inputDir)

	if password == "" {
		return "Directory encryption failed: password cannot be empty."
	}

	// Get all files in directory
	files, err := file.GetFilesInDirectory(inputDir)
	if err != nil {
		return fmt.Sprintf("Error reading directory: %v", err)
	}

	if len(files) == 0 {
		return "No files found in directory to encrypt."
	}

	logging.LogInfo("Found %d files to encrypt in directory", len(files))

	var successCount, failCount int
	var lastError string

	// Encrypt each file
	for i, filePath := range files {
		// Check for cancellation
		a.operationMutex.RLock()
		if a.currentOperation != nil && a.currentOperation.IsCancelled() {
			a.operationMutex.RUnlock()
			logging.LogInfo("Directory encryption cancelled by user")
			return fmt.Sprintf("Operation cancelled. Encrypted %d of %d files.", successCount, len(files))
		}
		a.operationMutex.RUnlock()

		// Emit progress for directory operation
		progress := float64(i) / float64(len(files)) * 100
		runtime.EventsEmit(a.ctx, "encryption:progress", map[string]interface{}{
			"Percentage":     progress,
			"Stage":          fmt.Sprintf("Encrypting file %d of %d", i+1, len(files)),
			"BytesProcessed": int64(i),
			"TotalBytes":     int64(len(files)),
		})

		// Encrypt individual file (without notifications)
		result := a.encryptFileInternal(filePath, password, hint, encryptionLevel, channel, encryptionMethod, deleteOriginal, false)

		if result == "success" {
			successCount++
			logging.LogInfo("Successfully encrypted: %s", filePath)
		} else {
			failCount++
			lastError = result
			logging.LogError("Failed to encrypt %s: %s", filePath, result)
		}
	}

	// Final progress update
	runtime.EventsEmit(a.ctx, "encryption:progress", map[string]interface{}{
		"Percentage":     100.0,
		"Stage":          "Directory encryption completed",
		"BytesProcessed": int64(len(files)),
		"TotalBytes":     int64(len(files)),
	})

	// Show completion notification
	runtime.EventsEmit(a.ctx, "notification", map[string]interface{}{
		"type":     "success",
		"title":    "Directory Encryption Completed",
		"message":  fmt.Sprintf("Encrypted %d files successfully. %d failed.", successCount, failCount),
		"duration": 8000,
	})

	logging.LogInfo("Directory encryption completed: %d success, %d failed", successCount, failCount)

	if failCount > 0 {
		return fmt.Sprintf("Directory encryption completed with errors. %d files encrypted, %d failed. Last error: %s", successCount, failCount, lastError)
	}

	return "success"
}

// DecryptDirectory decrypts all .gie files in a directory
func (a *App) DecryptDirectory(inputDir string, password string) string {
	// Create cancellable operation
	a.operationMutex.Lock()
	if a.currentOperation != nil {
		a.currentOperation.Cancel()
	}
	a.currentOperation = operation.NewOperation()
	a.operationMutex.Unlock()

	defer func() {
		a.operationMutex.Lock()
		a.currentOperation = nil
		a.operationMutex.Unlock()
	}()

	logging.LogInfo("Starting directory decryption: %s", inputDir)

	if password == "" {
		return "Directory decryption failed: password cannot be empty."
	}

	// Get all encrypted files in directory
	encryptedFiles, err := file.GetEncryptedFilesInDirectory(inputDir)
	if err != nil {
		return fmt.Sprintf("Error reading directory: %v", err)
	}

	if len(encryptedFiles) == 0 {
		return "No encrypted files (.gie) found in directory to decrypt."
	}

	logging.LogInfo("Found %d encrypted files to decrypt in directory", len(encryptedFiles))

	var successCount, failCount int
	var lastError string

	// Decrypt each file
	for i, filePath := range encryptedFiles {
		// Check for cancellation
		a.operationMutex.RLock()
		if a.currentOperation != nil && a.currentOperation.IsCancelled() {
			a.operationMutex.RUnlock()
			logging.LogInfo("Directory decryption cancelled by user")
			return fmt.Sprintf("Operation cancelled. Decrypted %d of %d files.", successCount, len(encryptedFiles))
		}
		a.operationMutex.RUnlock()

		// Emit progress for directory operation
		progress := float64(i) / float64(len(encryptedFiles)) * 100
		runtime.EventsEmit(a.ctx, "encryption:progress", map[string]interface{}{
			"Percentage":     progress,
			"Stage":          fmt.Sprintf("Decrypting file %d of %d", i+1, len(encryptedFiles)),
			"BytesProcessed": int64(i),
			"TotalBytes":     int64(len(encryptedFiles)),
		})

		// Decrypt individual file (without notifications)
		result := a.decryptFileInternal(filePath, password, false, false)

		if result == "success" {
			successCount++
			logging.LogInfo("Successfully decrypted: %s", filePath)
		} else {
			failCount++
			lastError = result
			logging.LogError("Failed to decrypt %s: %s", filePath, result)
		}
	}

	// Final progress update
	runtime.EventsEmit(a.ctx, "encryption:progress", map[string]interface{}{
		"Percentage":     100.0,
		"Stage":          "Directory decryption completed",
		"BytesProcessed": int64(len(encryptedFiles)),
		"TotalBytes":     int64(len(encryptedFiles)),
	})

	// Show completion notification
	runtime.EventsEmit(a.ctx, "notification", map[string]interface{}{
		"type":     "success",
		"title":    "Directory Decryption Completed",
		"message":  fmt.Sprintf("Decrypted %d files successfully. %d failed.", successCount, failCount),
		"duration": 8000,
	})

	logging.LogInfo("Directory decryption completed: %d success, %d failed", successCount, failCount)

	if failCount > 0 {
		return fmt.Sprintf("Directory decryption completed with errors. %d files decrypted, %d failed. Last error: %s", successCount, failCount, lastError)
	}

	return "success"
}

func (a *App) OpenExternalURL(url string) error {
	logging.LogInfo("Opening external URL: %s", url)

	runtime.BrowserOpenURL(a.ctx, url)

	return nil
}

func (a *App) SetTheme(theme string) error {
	if a.settings != nil {
		a.settings.Theme = theme
		return config.SaveSettings(a.settings)
	}
	return fmt.Errorf("settings not initialized")
}

/*
*
SetDeleteOriginal sets the value of the DeleteOriginal field in the app's settings and saves the settings to file.

If the app's settings are not initialized, it returns an error.

Parameters:
- deleteOriginal: The new value of the DeleteOriginal field.

Returns:
- An error if the app's settings are not initialized.
*/
func (a *App) SetDeleteOriginal(deleteOriginal bool) error {
	if a.settings != nil {
		a.settings.DeleteOriginal = deleteOriginal
		return config.SaveSettings(a.settings)
	}
	return fmt.Errorf("settings not initialized")
}

func (a *App) GetDebugLogs() []string {
	return logging.GetDebugLogs()
}

func (a *App) ClearDebugLogs() {
	logging.ClearDebugLogs()
	logging.LogInfo("Debug logs cleared by user")
}

func (a *App) GetSystemInfo() map[string]interface{} {
	var m goruntime.MemStats
	goruntime.ReadMemStats(&m)

	wd, _ := os.Getwd()

	return map[string]interface{}{
		"os":         goruntime.GOOS,
		"arch":       goruntime.GOARCH,
		"goVersion":  goruntime.Version(),
		"cpus":       goruntime.NumCPU(),
		"goroutines": goruntime.NumGoroutine(),
		"memAlloc":   m.Alloc / 1024,
		"memTotal":   m.TotalAlloc / 1024,
		"memSys":     m.Sys / 1024,
		"workingDir": wd,
		"logPath":    logging.GetLogPath(),
	}
}

// ResizeWindow resizes the window to the specified width and height
//
// Parameters:
// - width: the new width of the window
// - height: the new height of the window
//
// Returns: None
func (a *App) ResizeWindow(width, height int) {
	runtime.WindowSetSize(a.ctx, width, height)
	logging.LogInfo("Window resized to %dx%d", width, height)
}

// SetWindowResizable sets whether the window can be resized by the user
// Note: WindowSetResizable may not be available in all Wails versions
func (a *App) SetWindowResizable(resizable bool) {
	// This function is kept for compatibility but may not work in all versions
	logging.LogInfo("Window resizable setting requested: %v (may not be supported)", resizable)
}

// RestoreDefaultSettings restores the settings to their default values, preserving the theme.
//
// This function restores the settings to their default values, preserving the theme. The default
// values are:
// - LastUsedChannel: 50
// - LastUsedLevel: "Normal"
//
// The function returns an error if the settings are not initialized.
//
// Parameters:
//
//	None
//
// Returns:
//
//	error: An error if the settings are not initialized.
func (a *App) RestoreDefaultSettings() error {
	if a.settings != nil {
		// Preserve theme but reset other values to defaults
		currentTheme := a.settings.Theme
		a.settings.LastUsedChannel = 50
		a.settings.LastUsedLevel = "Normal"
		a.settings.Theme = currentTheme

		logging.LogInfo("Settings restored to defaults - Channel: %d, Level: %s, Theme: %s",
			a.settings.LastUsedChannel, a.settings.LastUsedLevel, a.settings.Theme)

		return config.SaveSettings(a.settings)
	}
	return fmt.Errorf("settings not initialized")
}

// UpdateChannelAndLevel updates only channel and level temporarily (not saved to disk)
func (a *App) UpdateChannelAndLevel(channel int, level string) {
	if a.settings != nil {
		a.settings.LastUsedChannel = channel
		a.settings.LastUsedLevel = level

		logging.LogInfo("Temporary settings update - Channel: %d, Level: %s", channel, level)

		// Emit event to update frontend
		runtime.EventsEmit(a.ctx, "settings:updated", a.settings)
	}
}

// UpdateChannel updates only the channel (for user input)
func (a *App) UpdateChannel(channel int) {
	if a.settings != nil {
		a.settings.LastUsedChannel = channel
		logging.LogInfo("User updated channel to: %d", channel)

		// Emit event to update frontend
		runtime.EventsEmit(a.ctx, "settings:updated", a.settings)
	}
}

// UpdateLevel updates only the level (for auto-detection)
func (a *App) UpdateLevel(level string) {
	if a.settings != nil {
		a.settings.LastUsedLevel = level
		logging.LogInfo("Auto-updated level to: %s", level)

		// Emit event to update frontend
		runtime.EventsEmit(a.ctx, "settings:updated", a.settings)
	}
}

// LoadFileForDecryption loads a file and automatically detects its encryption settings
func (a *App) LoadFileForDecryption(inputFile string) *FileMetadata {
	metadata := a.GetFileMetadata(inputFile)
	if metadata == nil {
		logging.LogInfo("Failed to read metadata from file: %s", inputFile)
		return nil
	}

	// Temporarily update settings to match file metadata (but don't save to disk)
	// The user's channel setting is preserved - only the level is auto-detected
	if a.settings != nil {
		a.settings.LastUsedLevel = metadata.EncryptionLevel

		logging.LogInfo("Auto-detected file settings - Level: %s, Channel: %d (user channel: %d)",
			metadata.EncryptionLevel, metadata.Channel, a.settings.LastUsedChannel)

		// Emit event to update frontend with detected settings
		runtime.EventsEmit(a.ctx, "file:loaded", map[string]interface{}{
			"metadata": metadata,
			"settings": a.settings,
		})
	}

	return metadata
}

func (a *App) ValidateFileChannel(inputFile string) bool {
	metadata := a.GetFileMetadata(inputFile)
	if metadata == nil {
		return false
	}

	isValid := metadata.Channel == a.settings.LastUsedChannel

	logging.LogInfo("Channel validation - File: %d, User: %d, Valid: %v",
		metadata.Channel, a.settings.LastUsedChannel, isValid)

	return isValid
}
