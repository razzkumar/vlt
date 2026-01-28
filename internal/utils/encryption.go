package utils

import (
	"fmt"
	"strings"

	"github.com/razzkumar/vlt/pkg/vault"
)

// IsEncryptedSingleValue checks if data contains a single encrypted value
func IsEncryptedSingleValue(data map[string]any) bool {
	if len(data) != 1 {
		return false
	}
	ciphertext, ok := data["ciphertext"].(string)
	return ok && strings.HasPrefix(ciphertext, "vault:v")
}

// IsPlaintextSingleValue checks if data contains a single plaintext value
func IsPlaintextSingleValue(data map[string]any) bool {
	if len(data) != 1 {
		return false
	}
	_, hasValue := data["value"]
	return hasValue
}

// IsEncryptedMultiValue checks if data contains multiple encrypted values
func IsEncryptedMultiValue(data map[string]any) bool {
	if len(data) == 0 {
		return false
	}

	for _, v := range data {
		if str, ok := v.(string); ok && strings.HasPrefix(str, "vault:v") {
			return true
		}
	}
	return false
}

// DecryptMultiValueData decrypts all encrypted values in a data map
func DecryptMultiValueData(data map[string]any, client vault.VaultClient, transitMount, keyName string) (map[string]any, error) {
	decryptedData := make(map[string]any)

	for k, v := range data {
		if ciphertext, ok := v.(string); ok && strings.HasPrefix(ciphertext, "vault:v") {
			plaintext, err := client.TransitDecrypt(transitMount, keyName, ciphertext)
			if err != nil {
				return nil, fmt.Errorf("decrypt %s: %w", k, err)
			}
			decryptedData[k] = string(plaintext)
		} else {
			decryptedData[k] = v
		}
	}

	return decryptedData, nil
}
