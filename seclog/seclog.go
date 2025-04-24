package seclog

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var (
	currentLevel = LevelInfo
	logger      = log.New(os.Stderr, "", log.LstdFlags)
)

// SetLevel sets the minimum log level
func SetLevel(level int) {
	currentLevel = level
}

// getCallerInfo returns file and line information about the caller
func getCallerInfo() string {
	_, file, line, ok := runtime.Caller(3) // Skip getCallerInfo, log function, and caller of log function
	if !ok {
		return "unknown:0"
	}
	parts := strings.Split(file, "/")
	if len(parts) > 2 {
		file = strings.Join(parts[len(parts)-2:], "/")
	}
	return fmt.Sprintf("%s:%d", file, line)
}

// formatMessage formats a log message with timestamp, level, and caller info
func formatMessage(level string, message string) string {
	caller := getCallerInfo()
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	return fmt.Sprintf("%s [%s] %s - %s", timestamp, level, caller, message)
}

// SecurityEvent logging - never suppress these
func SecurityEvent(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logger.Printf("SECURITY EVENT - %s", msg)
}

// Debug logs debug messages
func Debug(format string, args ...interface{}) {
	if currentLevel <= LevelDebug {
		msg := fmt.Sprintf(format, args...)
		logger.Println(formatMessage("DEBUG", msg))
	}
}

// Info logs informational messages
func Info(format string, args ...interface{}) {
	if currentLevel <= LevelInfo {
		msg := fmt.Sprintf(format, args...)
		logger.Println(formatMessage("INFO", msg))
	}
}

// Warn logs warning messages
func Warn(format string, args ...interface{}) {
	if currentLevel <= LevelWarn {
		msg := fmt.Sprintf(format, args...)
		logger.Println(formatMessage("WARN", msg))
	}
}

// Error logs error messages
func Error(format string, args ...interface{}) {
	if currentLevel <= LevelError {
		msg := fmt.Sprintf(format, args...)
		logger.Println(formatMessage("ERROR", msg))
	}
}

// Fatal logs fatal messages and exits
func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logger.Println(formatMessage("FATAL", msg))
	os.Exit(1)
}