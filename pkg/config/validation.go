package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Environment variable name validation
// Valid: starts with letter or underscore, contains only alphanumeric and underscores
var envVarNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Vault path validation
// Valid: alphanumeric, hyphens, underscores, and forward slashes
// Cannot start or end with slash, no double slashes
var vaultPathRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$`)

// ValidateEnvVarName checks if a string is a valid environment variable name
func ValidateEnvVarName(name string) error {
	if name == "" {
		return fmt.Errorf("environment variable name cannot be empty")
	}

	if !envVarNameRegex.MatchString(name) {
		return fmt.Errorf("invalid environment variable name %q: must start with letter or underscore, contain only alphanumeric characters and underscores", name)
	}

	return nil
}

// ValidateVaultPath checks if a string is a valid Vault path
func ValidateVaultPath(path string) error {
	if path == "" {
		return fmt.Errorf("vault path cannot be empty")
	}

	// Remove leading/trailing slashes for validation
	cleanPath := strings.Trim(path, "/")

	if cleanPath == "" {
		return fmt.Errorf("vault path cannot be only slashes")
	}

	// Check for double slashes
	if strings.Contains(path, "//") {
		return fmt.Errorf("invalid vault path %q: contains double slashes", path)
	}

	if !vaultPathRegex.MatchString(cleanPath) {
		return fmt.Errorf("invalid vault path %q: must contain only alphanumeric characters, hyphens, underscores, and forward slashes", path)
	}

	return nil
}

// ValidateSecretKey checks if a string is a valid secret key name
func ValidateSecretKey(key string) error {
	if key == "" {
		return fmt.Errorf("secret key cannot be empty")
	}

	// Secret keys are similar to env var names but can also contain hyphens and dots
	keyRegex := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*$`)
	if !keyRegex.MatchString(key) {
		return fmt.Errorf("invalid secret key %q: must start with letter or underscore, contain only alphanumeric characters, underscores, hyphens, and dots", key)
	}

	return nil
}

// ValidateInjectFormat validates the ENV_VAR=vault_path format
func ValidateInjectFormat(inject string) (envVar, vaultPath string, err error) {
	parts := strings.SplitN(inject, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid inject format %q: expected ENV_VAR=vault_path", inject)
	}

	envVar = strings.TrimSpace(parts[0])
	vaultPath = strings.TrimSpace(parts[1])

	if err := ValidateEnvVarName(envVar); err != nil {
		return "", "", fmt.Errorf("invalid inject %q: %w", inject, err)
	}

	if err := ValidateVaultPath(vaultPath); err != nil {
		return "", "", fmt.Errorf("invalid inject %q: %w", inject, err)
	}

	return envVar, vaultPath, nil
}
