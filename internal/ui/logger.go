package ui

import (
	"fmt"
	"io"
	"os"
)

// LogLevel represents the logging level
type LogLevel int

const (
	LevelError LogLevel = iota
	LevelWarning
	LevelInfo
	LevelVerbose
	LevelDebug
)

// Logger handles output with different verbosity levels
type Logger struct {
	level  LogLevel
	output io.Writer
}

var defaultLogger = &Logger{
	level:  LevelInfo,
	output: os.Stdout,
}

// SetLevel sets the global log level
func SetLevel(level LogLevel) {
	defaultLogger.level = level
}

// SetOutput sets the output writer
func SetOutput(w io.Writer) {
	defaultLogger.output = w
}

// GetLevel returns the current log level
func GetLevel() LogLevel {
	return defaultLogger.level
}

// Error prints an error message (always shown)
func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// Warning prints a warning message (shown at warning level and above)
func Warning(format string, args ...interface{}) {
	defaultLogger.Warning(format, args...)
}

// Info prints an info message (shown at info level and above)
func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

// Verbose prints a verbose message (shown at verbose level and above)
func Verbose(format string, args ...interface{}) {
	defaultLogger.Verbose(format, args...)
}

// Debug prints a debug message (only shown at debug level)
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

// Logger instance methods

func (l *Logger) Error(format string, args ...interface{}) {
	if l.level >= LevelError {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(l.output, "%s %s\n", Red("ERROR:"), msg)
	}
}

func (l *Logger) Warning(format string, args ...interface{}) {
	if l.level >= LevelWarning {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(l.output, "%s %s\n", Yellow("WARNING:"), msg)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.level >= LevelInfo {
		fmt.Fprintf(l.output, format+"\n", args...)
	}
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.level >= LevelVerbose {
		fmt.Fprintf(l.output, format+"\n", args...)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level >= LevelDebug {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(l.output, "%s %s\n", Gray("DEBUG:"), msg)
	}
}

// Success prints a success message with a checkmark
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Info(BrightGreen("✓") + " " + msg)
}

// Step prints a step indicator
func Step(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Info(Cyan("→") + " " + msg)
}
