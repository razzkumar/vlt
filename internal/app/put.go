package app

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/razzkumar/vlt/internal/utils"
	"github.com/razzkumar/vlt/pkg/config"
)

// PutOptions contains options for the Put operation
type PutOptions struct {
	KVMount       string
	KVPath        string
	TransitMount  string
	EncryptionKey string
	Key           string
	Value         string
	FromEnv       string
	FromFile      string
}

// Put stores secrets in Vault with optional encryption
func (a *App) Put(opts *PutOptions) error {
	effectiveEncryptionKey := config.GetEncryptionKey(opts.EncryptionKey)
	useEncryption := effectiveEncryptionKey != ""

	// Get existing data to merge with
	existingData, err := a.vaultClient.KVGet(opts.KVMount, opts.KVPath)
	if err != nil {
		// If secret doesn't exist, start with empty data
		existingData = make(map[string]interface{})
	}

	var finalData map[string]interface{}

	// Handle different data structures in existing data
	if utils.IsEncryptedSingleValue(existingData) || utils.IsPlaintextSingleValue(existingData) {
		finalData = make(map[string]interface{})
	} else {
		finalData = utils.MergeData(make(map[string]interface{}), existingData)
	}

	var newData map[string]interface{}

	if opts.FromEnv != "" {
		// Load from .env file
		newData, err = utils.LoadEnvFile(opts.FromEnv, a.vaultClient, opts.TransitMount, effectiveEncryptionKey, useEncryption)
		if err != nil {
			return fmt.Errorf("load env file: %w", err)
		}
		// Merge with existing data
		finalData = utils.MergeData(finalData, newData)
	} else if opts.FromFile != "" {
		// Load file content and use filename as key
		fileContent, err := os.ReadFile(opts.FromFile)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		// Use filename as key, base64 content as value
		filename := filepath.Base(opts.FromFile)
		base64Content := base64.StdEncoding.EncodeToString(fileContent)

		var value interface{}
		if useEncryption {
			ciphertext, err := a.vaultClient.TransitEncrypt(opts.TransitMount, effectiveEncryptionKey, []byte(base64Content))
			if err != nil {
				return fmt.Errorf("encrypt file content: %w", err)
			}
			value = ciphertext
		} else {
			value = base64Content
		}

		newData = map[string]interface{}{filename: value}
		// Merge with existing data
		finalData = utils.MergeData(finalData, newData)
	} else {
		// Single value (from --value, stdin, or key update)
		var secretValue []byte

		if opts.Value != "" {
			secretValue = []byte(opts.Value)
		} else {
			// Read from stdin
			secretValue, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
			// Remove trailing newline if reading from stdin
			if len(secretValue) > 0 && secretValue[len(secretValue)-1] == '\n' {
				secretValue = secretValue[:len(secretValue)-1]
			}
		}

		if len(secretValue) == 0 {
			return fmt.Errorf("no secret value provided")
		}

		// Handle key-specific update or single value storage
		if opts.Key != "" {
			// Update specific key in multi-value secret
			if useEncryption {
				ciphertext, err := a.vaultClient.TransitEncrypt(opts.TransitMount, effectiveEncryptionKey, secretValue)
				if err != nil {
					return fmt.Errorf("transit encrypt: %w", err)
				}
				finalData[opts.Key] = ciphertext
			} else {
				finalData[opts.Key] = string(secretValue)
			}
		} else {
			// Single value storage (backward compatibility)
			if useEncryption {
				ciphertext, err := a.vaultClient.TransitEncrypt(opts.TransitMount, effectiveEncryptionKey, secretValue)
				if err != nil {
					return fmt.Errorf("transit encrypt: %w", err)
				}
				finalData = map[string]interface{}{"ciphertext": ciphertext}
			} else {
				finalData = map[string]interface{}{"value": string(secretValue)}
			}
		}
	}

	if err := a.vaultClient.KVPut(opts.KVMount, opts.KVPath, finalData); err != nil {
		return fmt.Errorf("kv put: %w", err)
	}

	encryptionStatus := "plaintext"
	if useEncryption {
		encryptionStatus = "encrypted"
	}

	if opts.Key != "" {
		fmt.Printf("Updated key '%s' as %s: %s/%s\n", opts.Key, encryptionStatus, opts.KVMount, opts.KVPath)
	} else {
		secretsCount := len(finalData)
		fmt.Printf("Stored/updated %d secret(s) as %s: %s/%s\n", secretsCount, encryptionStatus, opts.KVMount, opts.KVPath)
	}

	return nil
}
