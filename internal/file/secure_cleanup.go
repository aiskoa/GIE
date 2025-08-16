package file

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"
)

// SecureDelete performs secure deletion of a file by overwriting it multiple times
func SecureDelete(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error checking file: %v", err)
	}

	fileSize := fileInfo.Size()

	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("error opening file for secure deletion: %v", err)
	}
	defer file.Close()

	passes := [][]byte{
		make([]byte, 1024*1024), // 1MB buffer of zeros
		make([]byte, 1024*1024), // 1MB buffer of ones
		make([]byte, 1024*1024), // 1MB buffer of random data
	}

	// Fill patterns
	for i := range passes[1] {
		passes[1][i] = 0xFF // All ones
	}
	rand.Read(passes[2]) // Random data

	// Perform overwrite passes
	for passNum, pattern := range passes {
		// Seek to beginning
		file.Seek(0, 0)

		var written int64
		for written < fileSize {
			remaining := fileSize - written
			writeSize := int64(len(pattern))
			if remaining < writeSize {
				writeSize = remaining
			}

			n, err := file.Write(pattern[:writeSize])
			if err != nil {
				return fmt.Errorf("error during secure overwrite pass %d: %v", passNum+1, err)
			}
			written += int64(n)
		}

		// Force write to disk
		file.Sync()

		// Small delay between passes
		time.Sleep(10 * time.Millisecond)
	}

	file.Close()

	// Finally, delete the file
	return os.Remove(filePath)
}

// CleanupTempFiles finds and securely deletes temporary files
func CleanupTempFiles(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("error reading directory: %v", err)
	}

	var cleanedFiles []string
	var errors []error

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Look for temporary files (.tmp, .todelete)
		if (len(name) >= 4 && name[len(name)-4:] == ".tmp") ||
			(len(name) >= 9 && name[len(name)-9:] == ".todelete") {
			fullPath := directory + string(os.PathSeparator) + name

			if err := SecureDelete(fullPath); err != nil {
				errors = append(errors, fmt.Errorf("failed to clean %s: %v", name, err))
			} else {
				cleanedFiles = append(cleanedFiles, name)
			}
		}
	}

	if len(cleanedFiles) > 0 {
		fmt.Printf("Securely cleaned %d temporary files: %v\n", len(cleanedFiles), cleanedFiles)
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup completed with %d errors: %v", len(errors), errors)
	}

	return nil
}
