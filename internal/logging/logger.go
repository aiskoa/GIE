package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	CRITICAL
)

var logLevelNames = map[LogLevel]string{
	DEBUG:    "DEBUG",
	INFO:     "INFO",
	WARNING:  "WARNING",
	ERROR:    "ERROR",
	CRITICAL: "CRITICAL",
}

type Logger struct {
	logFile *os.File
	logPath string
}

var globalLogger *Logger

// InitLogger initializes the global logger
func InitLogger() error {
	// Get user's documents directory or fallback to temp
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = os.TempDir()
	}

	logDir := filepath.Join(homeDir, ".gie", "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log file with timestamp
	timestamp := time.Now().Format("2006-01-02")
	logPath := filepath.Join(logDir, fmt.Sprintf("gie_%s.log", timestamp))

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}

	globalLogger = &Logger{
		logFile: logFile,
		logPath: logPath,
	}

	// Log system information on startup
	LogInfo("=== GIE v2.0.0 Started ===")
	LogInfo("OS: %s", runtime.GOOS)
	LogInfo("Architecture: %s", runtime.GOARCH)
	LogInfo("Go Version: %s", runtime.Version())
	LogInfo("Log file: %s", logPath)

	return nil
}

// CloseLogger closes the log file
func CloseLogger() {
	if globalLogger != nil && globalLogger.logFile != nil {
		LogInfo("=== GIE Session Ended ===")
		globalLogger.logFile.Close()
	}
}

// writeLog writes a log entry
func writeLog(level LogLevel, format string, args ...interface{}) {
	if globalLogger == nil || globalLogger.logFile == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelName := logLevelNames[level]
	message := fmt.Sprintf(format, args...)

	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	caller := "unknown"
	if ok {
		caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	logEntry := fmt.Sprintf("[%s] %s [%s] %s\n", timestamp, levelName, caller, message)

	// Write to file
	globalLogger.logFile.WriteString(logEntry)
	globalLogger.logFile.Sync() // Ensure immediate write

	// Also write to console for debugging
	fmt.Print(logEntry)
}

// Log functions
func LogDebug(format string, args ...interface{}) {
	writeLog(DEBUG, format, args...)
}

func LogInfo(format string, args ...interface{}) {
	writeLog(INFO, format, args...)
}

func LogWarning(format string, args ...interface{}) {
	writeLog(WARNING, format, args...)
}

func LogError(format string, args ...interface{}) {
	writeLog(ERROR, format, args...)
}

func LogCritical(format string, args ...interface{}) {
	writeLog(CRITICAL, format, args...)
}

// GetLogPath returns the current log file path
func GetLogPath() string {
	if globalLogger != nil {
		return globalLogger.logPath
	}
	return ""
}

// LogSystemInfo logs detailed system information
func LogSystemInfo() {
	LogInfo("=== System Information ===")
	LogInfo("Number of CPUs: %d", runtime.NumCPU())
	LogInfo("Number of Goroutines: %d", runtime.NumGoroutine())

	// Memory statistics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	LogInfo("Memory Allocated: %d KB", m.Alloc/1024)
	LogInfo("Total Allocations: %d", m.TotalAlloc/1024)
	LogInfo("System Memory: %d KB", m.Sys/1024)

	// Working directory
	if wd, err := os.Getwd(); err == nil {
		LogInfo("Working Directory: %s", wd)
	}

	LogInfo("=== End System Information ===")
}
