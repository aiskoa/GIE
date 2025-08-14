package file

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	MaxRetries = 10
	RetryDelay = 200 * time.Millisecond
)

// IsDirectory checks if the given path is a directory
func IsDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// GetFilesInDirectory recursively gets all files in a directory
func GetFilesInDirectory(dirPath string) ([]string, error) {
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

// GetEncryptedFilesInDirectory gets all .gie files in a directory
func GetEncryptedFilesInDirectory(dirPath string) ([]string, error) {
	var encryptedFiles []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
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
		return nil, err
	}

	return encryptedFiles, nil
}

// SafeDeleteFile safely deletes a file with retries
func SafeDeleteFile(filePath string, deleteOriginal bool) error {
	if !deleteOriginal {
		return nil // Don't delete if option is disabled
	}

	// Give the OS a moment to release file handles
	time.Sleep(100 * time.Millisecond)

	// Attempt to delete by renaming first (Windows-friendly approach)
	fileToDelete := filePath + ".todelete"
	renErr := os.Rename(filePath, fileToDelete)
	if renErr != nil {
		fmt.Printf("WARNING: Could not rename file %s for deletion: %v\n", filePath, renErr)
		return renErr
	}

	// Try to delete with retries
	for i := 0; i < MaxRetries; i++ {
		removeErr := os.Remove(fileToDelete)
		if removeErr == nil {
			fmt.Printf("DEBUG: Successfully deleted file: %s\n", fileToDelete)
			return nil
		}

		fmt.Printf("DEBUG: Deletion attempt %d for %s failed: %v. Retrying...\n", i+1, fileToDelete, removeErr)
		if i == MaxRetries-1 {
			fmt.Printf("WARNING: Could not delete file %s after multiple retries: %v\n", fileToDelete, removeErr)
			return removeErr
		}
		time.Sleep(RetryDelay)
	}

	return nil
}

// SafeRenameFile safely renames a file with retries
func SafeRenameFile(oldPath, newPath string) error {
	time.Sleep(500 * time.Millisecond) // Give OS time to release handles

	for i := 0; i < MaxRetries; i++ {
		err := os.Rename(oldPath, newPath)
		if err == nil {
			fmt.Printf("DEBUG: Successfully renamed %s to %s\n", oldPath, newPath)
			return nil
		}

		fmt.Printf("DEBUG: Rename attempt %d for %s failed: %v. Retrying...\n", i+1, oldPath, err)
		if i == MaxRetries-1 {
			return fmt.Errorf("error renaming file after multiple retries: %v", err)
		}
		time.Sleep(RetryDelay)
	}

	return nil
}

// IsPasswordValid checks if the password contains only allowed characters
func IsPasswordValid(password string) bool {
	// Allow alphanumeric and common special characters
	allowedCharsPattern := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_\-+=<>?,.:;{}\[\]|~` + "`" + `]*$`)
	return allowedCharsPattern.MatchString(password)
}

// IsPathValid checks if a file path is valid
func IsPathValid(path string) (bool, string) {
	if len(path) > 259 {
		return false, "The path is too long (max 259 characters)."
	}

	baseName := filepath.Base(path)

	// Check for invalid characters in the base name
	invalidCharPattern := regexp.MustCompile(`[<>:\"/\\|\?\*\x00-\x1F]`)
	if invalidCharPattern.MatchString(baseName) {
		return false, "The file name contains invalid characters (e.g., <, >, :, \", /, \\, |, ?, *) or control characters."
	}

	return true, ""
}

// ValidateChannel validates that channel is within acceptable range
func ValidateChannel(channel int) error {
	if channel < 0 {
		return fmt.Errorf("channel cannot be negative")
	}
	if channel > 65535 { // uint16 max value
		return fmt.Errorf("channel cannot exceed 65535")
	}
	return nil
}
