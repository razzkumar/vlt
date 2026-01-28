package utils

import (
	"fmt"
	"strings"
)

// ErrorCollector collects multiple errors and provides a summary
type ErrorCollector struct {
	errors []error
	prefix string
}

// NewErrorCollector creates a new ErrorCollector
func NewErrorCollector(prefix string) *ErrorCollector {
	return &ErrorCollector{
		prefix: prefix,
	}
}

// Add adds an error to the collector (nil errors are ignored)
func (ec *ErrorCollector) Add(err error) {
	if err != nil {
		ec.errors = append(ec.errors, err)
	}
}

// AddWithContext adds an error with additional context
func (ec *ErrorCollector) AddWithContext(context string, err error) {
	if err != nil {
		ec.errors = append(ec.errors, fmt.Errorf("%s: %w", context, err))
	}
}

// HasErrors returns true if any errors have been collected
func (ec *ErrorCollector) HasErrors() bool {
	return len(ec.errors) > 0
}

// Count returns the number of errors collected
func (ec *ErrorCollector) Count() int {
	return len(ec.errors)
}

// Error returns the collected errors as a single error
// Returns nil if no errors were collected
func (ec *ErrorCollector) Error() error {
	if !ec.HasErrors() {
		return nil
	}

	if len(ec.errors) == 1 {
		if ec.prefix != "" {
			return fmt.Errorf("%s: %w", ec.prefix, ec.errors[0])
		}
		return ec.errors[0]
	}

	var sb strings.Builder
	if ec.prefix != "" {
		sb.WriteString(ec.prefix)
		sb.WriteString(fmt.Sprintf(" (%d errors):\n", len(ec.errors)))
	} else {
		sb.WriteString(fmt.Sprintf("%d errors occurred:\n", len(ec.errors)))
	}

	for i, err := range ec.errors {
		sb.WriteString(fmt.Sprintf("  %d. %v\n", i+1, err))
	}

	return fmt.Errorf("%s", strings.TrimSuffix(sb.String(), "\n"))
}

// Errors returns all collected errors
func (ec *ErrorCollector) Errors() []error {
	return ec.errors
}

// IsTokenExpiredError checks if an error indicates an expired or invalid token
func IsTokenExpiredError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Common Vault token expiration error patterns
	tokenErrorPatterns := []string{
		"permission denied",
		"token expired",
		"token not found",
		"missing client token",
		"invalid token",
		"token is not renewable",
		"token has no",
		"403",
	}

	for _, pattern := range tokenErrorPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// IsConnectionError checks if an error indicates a connection problem
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	connectionErrorPatterns := []string{
		"connection refused",
		"no such host",
		"timeout",
		"dial tcp",
		"network is unreachable",
		"tls handshake",
		"certificate",
		"x509",
	}

	for _, pattern := range connectionErrorPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// WrapWithSuggestion wraps an error with a suggestion for how to fix it
func WrapWithSuggestion(err error, suggestion string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w\n  Suggestion: %s", err, suggestion)
}

// EnhanceError provides better error messages for common error types
func EnhanceError(err error) error {
	if err == nil {
		return nil
	}

	if IsTokenExpiredError(err) {
		return WrapWithSuggestion(err, "Your Vault token may have expired. Try re-authenticating with 'vault login' or provide a new token.")
	}

	if IsConnectionError(err) {
		return WrapWithSuggestion(err, "Cannot connect to Vault server. Check that VAULT_ADDR is correct and the server is running.")
	}

	return err
}
