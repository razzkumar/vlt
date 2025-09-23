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
	// Config holds the loaded configuration for file storage settings
	Config *config.Config
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
			if handled, err := a.handleFileValue(data, opts, opts.Key, value); err != nil {
				return err
			} else if handled {
				return nil
			}
			fmt.Print(value)
			return nil
		}

		if err := a.handleMultipleValuesWithFiles(data, opts, decryptedData); err != nil {
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
		if handled, err := a.handleFileValue(data, opts, opts.Key, value); err != nil {
			return err
		} else if handled {
			return nil
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
	if err := a.handleMultipleValuesWithFiles(data, opts); err != nil {
		return fmt.Errorf("handle multiple values: %w", err)
	}

	return nil
}

// GetFromConfigOptions holds options for the GetFromConfig operation
type GetFromConfigOptions struct {
	EncryptionKey string
	OutputJSON    bool
}

// GetFromConfig retrieves secrets from config file and displays them (legacy method)
func (a *App) GetFromConfig(configPath, encryptionKey string, outputJSON bool) error {
	opts := &GetFromConfigOptions{
		EncryptionKey: encryptionKey,
		OutputJSON:    outputJSON,
	}
	return a.GetFromConfigWithOptions(configPath, opts)
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

// handleMultipleValuesWithFiles processes multiple values, saving files where metadata indicates and outputting regular values
func (a *App) handleMultipleValuesWithFiles(originalData map[string]interface{}, opts *GetOptions, valuesData ...map[string]interface{}) error {
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

		handled, err := a.handleFileValue(originalData, opts, key, value)
		if err != nil {
			return err
		}
		if handled {
			filesProcessed++
			continue
		}

		regularValues[key] = value
	}

	// Output regular values if any exist
	if len(regularValues) > 0 {
		if opts.OutputJSON {
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

// handleFileValue saves a value as a file when configuration or metadata indicates it should
func (a *App) handleFileValue(originalData map[string]interface{}, opts *GetOptions, key string, value interface{}) (bool, error) {
	if opts == nil {
		return false, nil
	}

	fileOpts := a.resolveFileStorageOptions(originalData, opts, key)
	if fileOpts == nil {
		return false, nil
	}

	valueStr, ok := value.(string)
	if !ok {
		return true, fmt.Errorf("file content for %q is not a string", key)
	}

	if err := utils.SaveAsFileWithOptions(valueStr, *fileOpts); err != nil {
		return true, err
	}

	return true, nil
}

// resolveFileStorageOptions determines file storage options for a key using config or metadata
func (a *App) resolveFileStorageOptions(originalData map[string]interface{}, opts *GetOptions, key string) *utils.FileStorageOptions {
	if opts.Config != nil && opts.KVPath != "" {
		if configOpts := fileOptionsFromConfig(opts.Config, opts.KVPath, key); configOpts != nil {
			return configOpts
		}
	}

	if metadataOpts, ok := utils.FileOptionsFromMetadata(originalData, key); ok {
		return metadataOpts
	}

	return nil
}

// fileOptionsFromConfig extracts file storage options for a key using the provided config
func fileOptionsFromConfig(cfg *config.Config, kvPath, key string) *utils.FileStorageOptions {
	for _, secret := range cfg.Secrets {
		if secret.Path != kvPath || secret.Key != key {
			continue
		}
		if !secret.IsFileEntry() {
			continue
		}

		fileCfg := cfg.GetSecretFileConfig(&secret)
		createDir := false
		if fileCfg.CreateDir != nil {
			createDir = *fileCfg.CreateDir
		}

		return &utils.FileStorageOptions{
			Path:      fileCfg.Path,
			Mode:      fileCfg.Mode,
			CreateDir: createDir,
		}
	}

	return nil
}
