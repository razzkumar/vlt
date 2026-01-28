package app

import (
	"fmt"
	"strings"

	"github.com/razzkumar/vlt/internal/utils"
	"github.com/razzkumar/vlt/pkg/vault"
)

// DecryptOptions holds options for decryption operations
type DecryptOptions struct {
	TransitMount  string
	EncryptionKey string
}

// DecryptSingleValue decrypts a single encrypted value (ciphertext) from Vault data
// Returns the decrypted value or an error if decryption fails or key is missing
func (a *App) DecryptSingleValue(ciphertext string, opts *DecryptOptions) (string, error) {
	if opts.EncryptionKey == "" {
		return "", fmt.Errorf("encryption key required for encrypted secret")
	}

	plaintext, err := a.vaultClient.TransitDecrypt(opts.TransitMount, opts.EncryptionKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("transit decrypt: %w", err)
	}

	return string(plaintext), nil
}

// DecryptData decrypts Vault data based on its structure
// Returns the appropriate value based on whether it's encrypted/plaintext and single/multi-value
// If a specific key is requested, returns only that key's value
func (a *App) DecryptData(data map[string]interface{}, key string, opts *DecryptOptions) (interface{}, error) {
	// Check for single encrypted value (ciphertext key)
	if ciphertext, ok := data["ciphertext"].(string); ok && strings.HasPrefix(ciphertext, "vault:v") {
		decrypted, err := a.DecryptSingleValue(ciphertext, opts)
		if err != nil {
			return nil, err
		}
		return decrypted, nil
	}

	// Check for single plaintext value
	if len(data) == 1 {
		if value, ok := data["value"]; ok {
			return value, nil
		}
	}

	// Handle encrypted multi-value data
	if utils.IsEncryptedMultiValue(data) {
		if opts.EncryptionKey == "" {
			return nil, fmt.Errorf("encryption key required for encrypted secrets")
		}

		decryptedData, err := utils.DecryptMultiValueData(data, a.vaultClient, opts.TransitMount, opts.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt multi-value data: %w", err)
		}

		if key != "" {
			value, ok := decryptedData[key]
			if !ok {
				return nil, fmt.Errorf("key %q not found", key)
			}
			return value, nil
		}

		return decryptedData, nil
	}

	// Handle plaintext multi-value data
	if key != "" {
		value, ok := data[key]
		if !ok {
			return nil, fmt.Errorf("key %q not found", key)
		}
		return value, nil
	}

	return data, nil
}

// GetSecretValue extracts a single secret value from Vault data
// Handles encryption, single/multi-value secrets, and specific key extraction
func (a *App) GetSecretValue(client vault.VaultClient, kvMount, vaultPath string, opts *DecryptOptions) (string, error) {
	data, err := client.KVGet(kvMount, vaultPath)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", vaultPath, err)
	}

	// Handle single encrypted value
	if ciphertext, ok := data["ciphertext"].(string); ok && strings.HasPrefix(ciphertext, "vault:v") {
		return a.DecryptSingleValue(ciphertext, opts)
	}

	// Handle single plaintext value
	if value, ok := data["value"].(string); ok {
		return value, nil
	}

	// Handle single value with any key
	if len(data) == 1 {
		for _, v := range data {
			return fmt.Sprintf("%v", v), nil
		}
	}

	return "", fmt.Errorf("secret %s contains multiple values, cannot extract single value", vaultPath)
}
