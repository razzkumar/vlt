package app

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/razzkumar/vlt/internal/utils"
)

// ImportOptions contains options for the Import operation
type ImportOptions struct {
	KVMount       string
	Path          string
	TransitMount  string
	EncryptionKey string
	Input         string // input file path
	Format        string // "json" or "env" (auto-detected if empty)
	Merge         bool   // merge with existing data
}

// Import imports secrets from a file to Vault
func (a *App) Import(opts *ImportOptions) error {
	if opts.Path == "" {
		return fmt.Errorf("path is required")
	}

	if opts.Input == "" {
		return fmt.Errorf("input file is required")
	}

	kvMount := opts.KVMount
	if kvMount == "" {
		kvMount = "home"
	}

	// Read input file
	content, err := os.ReadFile(opts.Input)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Auto-detect format
	format := opts.Format
	if format == "" {
		if strings.HasSuffix(opts.Input, ".json") {
			format = "json"
		} else if strings.HasSuffix(opts.Input, ".env") {
			format = "env"
		} else {
			// Try to parse as JSON
			var test map[string]interface{}
			if json.Unmarshal(content, &test) == nil {
				format = "json"
			} else {
				format = "env"
			}
		}
	}

	// Parse input
	var data map[string]interface{}
	switch format {
	case "json":
		if err := json.Unmarshal(content, &data); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	case "env":
		envData, err := utils.LoadEnvFileAsPlaintext(opts.Input)
		if err != nil {
			return fmt.Errorf("failed to parse env file: %w", err)
		}
		data = envData
	default:
		return fmt.Errorf("unsupported format: %s (use 'json' or 'env')", format)
	}

	// Merge with existing data if requested
	if opts.Merge {
		existing, err := a.vaultClient.KVGet(kvMount, opts.Path)
		if err == nil && existing != nil {
			for k, v := range data {
				existing[k] = v
			}
			data = existing
		}
		// Ignore error - path may not exist yet
	}

	// Encrypt if encryption key is provided
	if opts.EncryptionKey != "" {
		transitMount := opts.TransitMount
		if transitMount == "" {
			transitMount = "transit"
		}

		encryptedData := make(map[string]interface{})
		for k, v := range data {
			if str, ok := v.(string); ok {
				encrypted, err := a.vaultClient.TransitEncrypt(transitMount, opts.EncryptionKey, []byte(str))
				if err != nil {
					return fmt.Errorf("failed to encrypt key %s: %w", k, err)
				}
				encryptedData[k] = encrypted
			} else {
				encryptedData[k] = v
			}
		}
		data = encryptedData
	}

	// Store in Vault
	if err := a.vaultClient.KVPut(kvMount, opts.Path, data); err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	return nil
}
