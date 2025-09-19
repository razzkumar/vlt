package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/razzkumar/vlt/pkg/vault"
)

// LoadEnvFileAsPlaintext loads a .env file and returns plaintext data map (no vault client needed)
func LoadEnvFileAsPlaintext(path string) (map[string]any, error) {
	// Use godotenv to parse the .env file
	envMap, err := godotenv.Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read .env file: %w", err)
	}

	data := make(map[string]any)
	for key, value := range envMap {
		data[key] = value
	}

	return data, nil
}

// LoadEnvFile loads a .env file and returns encrypted/plaintext data map
func LoadEnvFile(path string, client *vault.Client, transitMount, keyName string, useEncryption bool) (map[string]any, error) {
	// Use godotenv to parse the .env file
	envMap, err := godotenv.Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read .env file: %w", err)
	}

	data := make(map[string]any)

	for key, value := range envMap {
		if useEncryption {
			ciphertext, err := client.TransitEncrypt(transitMount, keyName, []byte(value))
			if err != nil {
				return nil, fmt.Errorf("encrypt %s: %w", key, err)
			}
			data[key] = ciphertext
		} else {
			data[key] = value
		}
	}

	return data, nil
}

// LoadFileAsBase64 reads a file and encodes it as base64
func LoadFileAsBase64(path string, client *vault.Client, transitMount, keyName string, useEncryption bool) (map[string]any, error) {
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	base64Content := base64.StdEncoding.EncodeToString(fileContent)

	if useEncryption {
		ciphertext, err := client.TransitEncrypt(transitMount, keyName, []byte(base64Content))
		if err != nil {
			return nil, fmt.Errorf("encrypt file content: %w", err)
		}
		return map[string]any{"ciphertext": ciphertext}, nil
	}

	return map[string]any{"value": base64Content}, nil
}

// LoadFileAsKeyValue reads a file and uses filename as key, base64 content as value
func LoadFileAsKeyValue(path string, client *vault.Client, transitMount, keyName string, useEncryption bool) (map[string]any, error) {
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	base64Content := base64.StdEncoding.EncodeToString(fileContent)
	
	// Extract filename without path as the key
	filename := filepath.Base(path)
	
	data := make(map[string]any)
	
	if useEncryption {
		ciphertext, err := client.TransitEncrypt(transitMount, keyName, []byte(base64Content))
		if err != nil {
			return nil, fmt.Errorf("encrypt file content: %w", err)
		}
		data[filename] = ciphertext
	} else {
		data[filename] = base64Content
	}
	
	// Add metadata to indicate this is file content
	data[filename+"_metadata"] = map[string]any{"type": "file"}
	
	return data, nil
}

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
func DecryptMultiValueData(data map[string]any, client *vault.Client, transitMount, keyName string) (map[string]any, error) {
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

// OutputJSON outputs data as formatted JSON
func OutputJSON(data map[string]any) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

// OutputEnvFormat outputs data in .env format
func OutputEnvFormat(data map[string]any) {
	for k, v := range data {
		fmt.Printf("%s=%v\n", k, v)
	}
}

// MergeData merges new data into existing data, preserving existing values and adding/updating new ones
func MergeData(existing, new map[string]any) map[string]any {
	result := make(map[string]any)

	// Copy existing data
	for k, v := range existing {
		result[k] = v
	}

	// Add/update with new data
	for k, v := range new {
		result[k] = v
	}

	return result
}

// HasFileMetadata checks if a key has associated file metadata
func HasFileMetadata(data map[string]any, key string) bool {
	metadataKey := key + "_metadata"
	metadata, exists := data[metadataKey]
	if !exists {
		return false
	}
	
	metadataMap, ok := metadata.(map[string]any)
	if !ok {
		return false
	}
	
	fileType, ok := metadataMap["type"].(string)
	return ok && fileType == "file"
}

// SaveAsFile decodes base64 content and saves it as a file
func SaveAsFile(filename, base64Content string) error {
	decodedContent, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		return fmt.Errorf("decode base64 content for %s: %w", filename, err)
	}
	
	if err := os.WriteFile(filename, decodedContent, 0644); err != nil {
		return fmt.Errorf("write file %s: %w", filename, err)
	}
	
	fmt.Printf("File saved: %s\n", filename)
	return nil
}
