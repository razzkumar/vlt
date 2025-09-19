package app

import (
	"fmt"
	"os"

	"github.com/razzkumar/vlt/internal/utils"
	"github.com/razzkumar/vlt/pkg/config"
)

// JSONOptions contains options for the JSON operation
type JSONOptions struct {
	TransitMount  string
	EncryptionKey string
	EnvFile       string
}

// JSON encrypts .env file content and outputs as JSON
func (a *App) JSON(opts *JSONOptions) error {
	effectiveEncryptionKey := config.GetEncryptionKey(opts.EncryptionKey)
	useEncryption := config.ShouldUseEncryption(effectiveEncryptionKey)

	// Default to .env if no file specified
	envFile := opts.EnvFile
	if envFile == "" {
		envFile = ".env"
	}

	// Check if file exists
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		return fmt.Errorf("env file not found: %s", envFile)
	}

	var data map[string]interface{}
	var err error

	if useEncryption {
		// Load and encrypt the env file using vault client
		data, err = utils.LoadEnvFile(envFile, a.vaultClient, opts.TransitMount, effectiveEncryptionKey, useEncryption)
		if err != nil {
			return fmt.Errorf("load env file: %w", err)
		}
	} else {
		// Load as plaintext without vault client
		data, err = utils.LoadEnvFileAsPlaintext(envFile)
		if err != nil {
			return fmt.Errorf("load env file: %w", err)
		}
	}

	// Output as JSON
	if err := utils.OutputJSON(data); err != nil {
		return fmt.Errorf("output json: %w", err)
	}

	return nil
}
