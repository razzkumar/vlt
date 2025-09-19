package app

import (
	"fmt"
	"strings"

	"github.com/razzkumar/vlt/internal/utils"
	"github.com/razzkumar/vlt/pkg/config"
)

// GetOptions contains options for the Get operation
type GetOptions struct {
	KVMount       string
	KVPath        string
	TransitMount  string
	EncryptionKey string
	Key           string
	OutputJSON    bool
}

// Get retrieves and optionally decrypts secrets from Vault
func (a *App) Get(opts *GetOptions) error {
	effectiveEncryptionKey := config.GetEncryptionKey(opts.EncryptionKey)

	// Get from KV
	data, err := a.vaultClient.KVGet(opts.KVMount, opts.KVPath)
	if err != nil {
		return fmt.Errorf("kv get: %w", err)
	}

	// Try to get single encrypted data first
	ciphertext, hasCiphertext := data["ciphertext"].(string)
	if hasCiphertext && ciphertext != "" {
		// Single encrypted data - requires key
		if effectiveEncryptionKey == "" {
			return fmt.Errorf("--encryption-key is required for encrypted secrets")
		}
		plaintext, err := a.vaultClient.TransitDecrypt(opts.TransitMount, effectiveEncryptionKey, ciphertext)
		if err != nil {
			return fmt.Errorf("transit decrypt: %w", err)
		}
		fmt.Print(string(plaintext))
		return nil
	}

	// Handle encrypted multi-value data
	if utils.IsEncryptedMultiValue(data) {
		if effectiveEncryptionKey == "" {
			return fmt.Errorf("--encryption-key is required for encrypted secrets")
		}

		decryptedData, err := utils.DecryptMultiValueData(data, a.vaultClient, opts.TransitMount, effectiveEncryptionKey)
		if err != nil {
			return fmt.Errorf("decrypt multi-value data: %w", err)
		}

		if opts.Key != "" {
			value, ok := decryptedData[opts.Key]
			if !ok {
				return fmt.Errorf("key %q not found", opts.Key)
			}
			fmt.Print(value)
			return nil
		}

		if err := a.handleMultipleValuesWithFiles(data, opts.OutputJSON, decryptedData); err != nil {
			return fmt.Errorf("handle multiple values: %w", err)
		}
		return nil
	}

	// Handle plaintext multi-value data
	if opts.Key != "" {
		value, ok := data[opts.Key]
		if !ok {
			return fmt.Errorf("key %q not found", opts.Key)
		}
		fmt.Print(value)
		return nil
	}

	if len(data) == 1 {
		// Single plaintext value
		if value, ok := data["value"].(string); ok {
			fmt.Print(value)
			return nil
		}
	}

	// Multiple values - handle files and regular values
	if err := a.handleMultipleValuesWithFiles(data, opts.OutputJSON); err != nil {
		return fmt.Errorf("handle multiple values: %w", err)
	}

	return nil
}

// GetFromConfig retrieves secrets from config file and displays them
func (a *App) GetFromConfig(configPath, encryptionKey string, outputJSON bool) error {
	cfg, err := a.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	effectiveEncryptionKey := config.GetEncryptionKey(encryptionKey)

	// Use the shared logic for loading secrets
	envVars, err := a.loadSecretsFromConfig(cfg, "home", "transit", effectiveEncryptionKey)
	if err != nil {
		return fmt.Errorf("load secrets from config: %w", err)
	}

	// Convert to interface map for output functions
	data := make(map[string]interface{})
	for k, v := range envVars {
		data[k] = v
	}

	// Output in requested format
	if outputJSON {
		if err := utils.OutputJSON(data); err != nil {
			return fmt.Errorf("output json: %w", err)
		}
	} else {
		utils.OutputEnvFormat(data)
	}

	return nil
}

// handleMultipleValuesWithFiles processes multiple values, saving files where metadata indicates and outputting regular values
func (a *App) handleMultipleValuesWithFiles(originalData map[string]interface{}, outputJSON bool, valuesData ...map[string]interface{}) error {
	// Use valuesData if provided (for decrypted data), otherwise use originalData
	var valuesToProcess map[string]interface{}
	if len(valuesData) > 0 && valuesData[0] != nil {
		valuesToProcess = valuesData[0]
	} else {
		valuesToProcess = originalData
	}

	regularValues := make(map[string]interface{})
	filesProcessed := 0

	for key, value := range valuesToProcess {
		// Skip metadata keys
		if strings.HasSuffix(key, "_metadata") {
			continue
		}

		// Check if this key has file metadata
		if utils.HasFileMetadata(originalData, key) {
			// Save as file
			if valueStr, ok := value.(string); ok {
				if err := utils.SaveAsFile(key, valueStr); err != nil {
					return err
				}
				filesProcessed++
			} else {
				return fmt.Errorf("file content for %q is not a string", key)
			}
		} else {
			// Regular value - add to output
			regularValues[key] = value
		}
	}

	// Output regular values if any exist
	if len(regularValues) > 0 {
		if outputJSON {
			if err := utils.OutputJSON(regularValues); err != nil {
				return fmt.Errorf("output json: %w", err)
			}
		} else {
			utils.OutputEnvFormat(regularValues)
		}
	}

	// Show summary if files were processed
	if filesProcessed > 0 {
		if len(regularValues) > 0 {
			fmt.Printf("\nProcessed %d file(s) and %d regular value(s)\n", filesProcessed, len(regularValues))
		} else {
			fmt.Printf("Processed %d file(s)\n", filesProcessed)
		}
	}

	return nil
}
