package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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


// FileStorageOptions holds options for file storage
type FileStorageOptions struct {
	Path      string // Full path where the file should be saved
	Mode      string // File permissions in octal (e.g., "0644")
	CreateDir bool   // Whether to create directories if they don't exist
}

// SaveAsFile decodes base64 content and saves it as a file (legacy function for backward compatibility)
func SaveAsFile(filename, base64Content string) error {
	opts := FileStorageOptions{
		Path:      filename,
		Mode:      "0644",
		CreateDir: false,
	}
	return SaveAsFileWithOptions(base64Content, opts)
}

// SaveAsFileWithOptions saves content to file with configurable options
// Automatically detects if content is base64-encoded or plain text
func SaveAsFileWithOptions(content string, opts FileStorageOptions) error {
	var fileContent []byte
	
	// Try to decode as base64 first (for files uploaded with --from-file)
	if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
		// Successfully decoded as base64, use decoded content
		fileContent = decoded
	} else {
		// Not valid base64, treat as plain text (for normal secret keys)
		fileContent = []byte(content)
	}
	
	// Create directory if needed
	if opts.CreateDir {
		dir := filepath.Dir(opts.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	
	// Parse file permissions
	mode, err := parseFileMode(opts.Mode)
	if err != nil {
		return fmt.Errorf("invalid file mode %s: %w", opts.Mode, err)
	}
	
	if err := os.WriteFile(opts.Path, fileContent, mode); err != nil {
		return fmt.Errorf("write file %s: %w", opts.Path, err)
	}

	fmt.Printf("File saved: %s (mode: %s)\n", opts.Path, opts.Mode)
	return nil
}

// parseFileMode parses octal file mode string (e.g., "0644") to os.FileMode
func parseFileMode(modeStr string) (os.FileMode, error) {
	if modeStr == "" {
		return 0644, nil // default
	}

	// Parse octal string
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal mode: %w", err)
	}

	return os.FileMode(mode), nil
}
