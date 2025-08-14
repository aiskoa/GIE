package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Settings represents application settings
type Settings struct {
	Theme             string `json:"theme"`
	DefaultEncryption string `json:"defaultEncryption"`
	DeleteOriginal    bool   `json:"deleteOriginal"`
	LastUsedLevel     string `json:"lastUsedLevel"`
	LastUsedChannel   int    `json:"lastUsedChannel"`
}

// DefaultSettings returns default application settings
func DefaultSettings() *Settings {
	return &Settings{
		Theme:             "dark",
		DefaultEncryption: "AES-CTR",
		DeleteOriginal:    false,
		LastUsedLevel:     "Normal",
		LastUsedChannel:   50,
	}
}

// GetConfigDir returns the configuration directory path
func GetConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error getting user home directory: %v", err)
	}

	configDir := filepath.Join(homeDir, ".gie")

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("error creating config directory: %v", err)
	}

	return configDir, nil
}

// GetSettingsPath returns the path to the settings file
func GetSettingsPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "settings.json"), nil
}

// LoadSettings loads settings from file or returns defaults
func LoadSettings() (*Settings, error) {
	settingsPath, err := GetSettingsPath()
	if err != nil {
		return DefaultSettings(), nil // Return defaults if can't get path
	}

	// Start with default settings
	settings := DefaultSettings()

	// If file exists, only load the theme (other settings always use defaults)
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		data, err := os.ReadFile(settingsPath)
		if err == nil {
			var savedSettings Settings
			if json.Unmarshal(data, &savedSettings) == nil {
				// Only preserve the theme from saved settings
				settings.Theme = savedSettings.Theme
			}
		}
	}

	// Validate and fix encryption method if invalid
	validMethods := []string{"AES-CTR", "AES-GCM"}
	isValid := false
	for _, method := range validMethods {
		if settings.DefaultEncryption == method {
			isValid = true
			break
		}
	}

	// If encryption method is invalid, reset to default
	if !isValid {
		settings.DefaultEncryption = "AES-CTR"
	}

	// Always ensure channel and level are defaults
	settings.LastUsedChannel = 50
	settings.LastUsedLevel = "Normal"

	return settings, nil
}

// SaveSettings saves only persistent settings to file (theme, deleteOriginal, defaultEncryption)
// Channel and level are never saved - they always reset to defaults
func SaveSettings(settings *Settings) error {
	settingsPath, err := GetSettingsPath()
	if err != nil {
		return fmt.Errorf("error getting settings path: %v", err)
	}

	// Create a settings object with only the values we want to persist
	persistentSettings := &Settings{
		Theme:             settings.Theme,
		DefaultEncryption: settings.DefaultEncryption,
		DeleteOriginal:    settings.DeleteOriginal,
		// Never save these - they always use defaults
		LastUsedLevel:   "Normal",
		LastUsedChannel: 50,
	}

	data, err := json.MarshalIndent(persistentSettings, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling settings: %v", err)
	}

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return fmt.Errorf("error writing settings file: %v", err)
	}

	return nil
}
