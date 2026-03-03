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
	// Raw outputs the value without any formatting or newlines
	Raw bool
	// Default is the value to return if the secret is not found
	Default string
	// Config holds the loaded configuration for file storage settings
	Config *config.Config
}

// Get retrieves and optionally decrypts secrets from Vault
func (a *App) Get(opts *GetOptions) error {
	// Validate inputs
	if err := config.ValidateVaultPath(opts.KVPath); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	if opts.Key != "" {
		if err := config.ValidateSecretKey(opts.Key); err != nil {
			return fmt.Errorf("invalid key: %w", err)
		}
	}

	effectiveEncryptionKey := config.GetEncryptionKey(opts.EncryptionKey)

	// Get from KV
	data, err := a.vaultClient.KVGet(opts.KVMount, opts.KVPath)
	if err != nil {
		// If we have a default value, use it instead of failing
		if opts.Default != "" {
			a.outputValue(opts.Default, opts.Raw)
			return nil
		}
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
		a.outputValue(string(plaintext), opts.Raw)
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
				if opts.Default != "" {
					a.outputValue(opts.Default, opts.Raw)
					return nil
				}
				return fmt.Errorf("key %q not found", opts.Key)
			}
			a.outputValue(fmt.Sprintf("%v", value), opts.Raw)
			return nil
		}

		if err := a.handleMultipleValues(decryptedData, opts.OutputJSON); err != nil {
			return fmt.Errorf("handle multiple values: %w", err)
		}
		return nil
	}

	// Handle plaintext multi-value data
	if opts.Key != "" {
		value, ok := data[opts.Key]
		if !ok {
			if opts.Default != "" {
				a.outputValue(opts.Default, opts.Raw)
				return nil
			}
			return fmt.Errorf("key %q not found", opts.Key)
		}
		a.outputValue(fmt.Sprintf("%v", value), opts.Raw)
		return nil
	}

	if len(data) == 1 {
		// Single plaintext value
		if value, ok := data["value"].(string); ok {
			a.outputValue(value, opts.Raw)
			return nil
		}
	}

	// Multiple values - output as environment variables
	if err := a.handleMultipleValues(data, opts.OutputJSON); err != nil {
		return fmt.Errorf("handle multiple values: %w", err)
	}

	return nil
}

// outputValue outputs a single value, optionally in raw format
func (a *App) outputValue(value string, raw bool) {
	if raw {
		fmt.Print(value)
	} else {
		fmt.Println(value)
	}
}

// handleMultipleValues processes multiple values and outputs them
func (a *App) handleMultipleValues(data map[string]interface{}, outputJSON bool) error {
	// Skip metadata keys and output regular values
	regularValues := make(map[string]interface{})
	for key, value := range data {
		// Skip metadata keys
		if strings.HasSuffix(key, "_metadata") {
			continue
		}
		regularValues[key] = value
	}

	// Output regular values
	if len(regularValues) > 0 {
		if outputJSON {
			if err := utils.OutputJSON(regularValues); err != nil {
				return fmt.Errorf("output json: %w", err)
			}
		} else {
			utils.OutputEnvFormat(regularValues)
		}
	}

	return nil
}

// GetFromConfigOptions holds options for the GetFromConfig operation
type GetFromConfigOptions struct {
	EncryptionKey string
	OutputJSON    bool
}

// GetFromConfigWithOptions retrieves secrets from config file with file storage options
func (a *App) GetFromConfigWithOptions(configPath string, opts *GetFromConfigOptions) error {
	cfg, err := a.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	effectiveEncryptionKey := config.GetEncryptionKey(opts.EncryptionKey)

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
	if opts.OutputJSON {
		if err := utils.OutputJSON(data); err != nil {
			return fmt.Errorf("output json: %w", err)
		}
	} else {
		utils.OutputEnvFormat(data)
	}

	return nil
}
