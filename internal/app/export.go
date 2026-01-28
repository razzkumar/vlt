package app

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ExportOptions contains options for the Export operation
type ExportOptions struct {
	KVMount       string
	Path          string
	TransitMount  string
	EncryptionKey string
	Output        string // output file path (empty for stdout)
	Format        string // "json" or "env"
}

// Export exports secrets from Vault to a file
func (a *App) Export(opts *ExportOptions) error {
	if opts.Path == "" {
		return fmt.Errorf("path is required")
	}

	kvMount := opts.KVMount
	if kvMount == "" {
		kvMount = "home"
	}

	format := opts.Format
	if format == "" {
		format = "json"
	}

	// Get the secret data
	data, err := a.vaultClient.KVGet(kvMount, opts.Path)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// Decrypt if encryption key is provided
	if opts.EncryptionKey != "" {
		transitMount := opts.TransitMount
		if transitMount == "" {
			transitMount = "transit"
		}

		decryptedData := make(map[string]interface{})
		for k, v := range data {
			if str, ok := v.(string); ok && strings.HasPrefix(str, "vault:v1:") {
				decrypted, err := a.vaultClient.TransitDecrypt(transitMount, opts.EncryptionKey, str)
				if err != nil {
					return fmt.Errorf("failed to decrypt key %s: %w", k, err)
				}
				decryptedData[k] = string(decrypted)
			} else {
				decryptedData[k] = v
			}
		}
		data = decryptedData
	}

	// Format output
	var output string
	switch format {
	case "json":
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		output = string(jsonBytes)
	case "env":
		var lines []string
		for k, v := range data {
			if str, ok := v.(string); ok {
				// Escape special characters in value
				escaped := strings.ReplaceAll(str, "\\", "\\\\")
				escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
				escaped = strings.ReplaceAll(escaped, "\n", "\\n")
				lines = append(lines, fmt.Sprintf("%s=\"%s\"", k, escaped))
			}
		}
		sort.Strings(lines)
		output = strings.Join(lines, "\n")
	default:
		return fmt.Errorf("unsupported format: %s (use 'json' or 'env')", format)
	}

	// Write output
	if opts.Output == "" || opts.Output == "-" {
		fmt.Println(output)
	} else {
		if err := os.WriteFile(opts.Output, []byte(output+"\n"), 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Exported to: %s\n", opts.Output)
	}

	return nil
}
