package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/razzkumar/vlt/internal/utils"
	"github.com/razzkumar/vlt/pkg/config"
)

// LoadConfig loads configuration from a YAML file
func (a *App) LoadConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml config: %w", err)
	}

	// Validate the config
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// GenerateEnvFile generates a .env file from multiple vault secrets
func (a *App) GenerateEnvFile(configPath, outputPath string, encryptionKey string) error {
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

	// Convert to env file format
	var envLines []string
	for k, v := range envVars {
		envLines = append(envLines, fmt.Sprintf("%s=%s", k, v))
	}

	// Write to file
	content := strings.Join(envLines, "\n")
	if len(envLines) > 0 {
		content += "\n" // Add final newline
	}

	cleanOutputPath := filepath.Clean(outputPath)
	if utils.ContainsDotDot(cleanOutputPath) {
		return fmt.Errorf("invalid output path: path traversal detected in %s", outputPath)
	}
	if err := os.WriteFile(cleanOutputPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Generated %s with %d secrets\n", outputPath, len(envLines))
	return nil
}

// loadSecretsFromConfig loads secrets from YAML config and returns as env vars
func (a *App) loadSecretsFromConfig(cfg *config.Config, kvMount, transitMount, encryptionKey string) (map[string]string, error) {
	envVars := make(map[string]string)

	for _, secret := range cfg.Secrets {
		if secret.IsDirEntry() {
			// Directory format: save all keys from path as individual files in directory
			if err := a.handleDirEntry(cfg, &secret, kvMount, transitMount, encryptionKey); err != nil {
				return nil, fmt.Errorf("failed to save directory files for path %s: %w", secret.Path, err)
			}
			// Don't add to envVars since they're files
		} else if secret.IsPathAllKeys() {
			// New format: load all keys from a path as environment variables
			pathEnvVars, err := a.loadAllKeysFromPath(cfg, secret.Path, kvMount, transitMount, encryptionKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load secrets from path %s: %w", secret.Path, err)
			}
			for k, v := range pathEnvVars {
				envVars[k] = v
			}
		} else if secret.IsPathSingleKey() {
			// Selective format: load single key from path
			if secret.IsFileEntry() {
				// File entry - save to file instead of env var
				if err := a.handleFileEntry(cfg, &secret, kvMount, transitMount, encryptionKey); err != nil {
					return nil, fmt.Errorf("failed to save file for key %s from path %s: %w", secret.Key, secret.Path, err)
				}
				// Don't add to envVars since it's a file
			} else {
				secretValue, err := a.loadSingleKeyFromPath(cfg, &secret, kvMount, transitMount, encryptionKey)
				if err != nil {
					return nil, fmt.Errorf("failed to load key %s from path %s: %w", secret.Key, secret.Path, err)
				}
				envVars[secret.GetEnvKeyName()] = secretValue
			}
		} else if secret.IsIndividual() {
			// Old format: individual secret mapping
			secretValue, err := a.loadIndividualSecret(cfg, &secret, kvMount, transitMount, encryptionKey)
			if err != nil {
				if secret.Required {
					return nil, err
				}
				fmt.Fprintf(os.Stderr, "warning: %v\n", err)
				continue
			}
			envVars[secret.EnvVar] = secretValue
		} else {
			fmt.Fprintf(os.Stderr, "warning: skipping invalid secret entry: either 'path' or 'kv_path+env_var' must be specified\n")
			continue
		}
	}

	return envVars, nil
}

// loadAllKeysFromPath loads all keys from a Vault path as environment variables
func (a *App) loadAllKeysFromPath(cfg *config.Config, vaultPath, kvMount, transitMount, encryptionKey string) (map[string]string, error) {
	envVars := make(map[string]string)

	// Get all data from the Vault path
	data, err := a.vaultClient.KVGet(config.NonEmpty("", cfg.KV.Mount, kvMount), vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets from path %s: %w", vaultPath, err)
	}

	// Handle encrypted multi-value data
	if utils.IsEncryptedMultiValue(data) {
		encKeyForDecrypt := config.NonEmpty(encryptionKey, cfg.GetTransitKey(), "")
		if encKeyForDecrypt == "" {
			return nil, fmt.Errorf("encryption key required for encrypted secrets at path %s", vaultPath)
		}

		decryptedData, err := utils.DecryptMultiValueData(data, a.vaultClient, cfg.GetTransitMount(transitMount), encKeyForDecrypt)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secrets from path %s: %w", vaultPath, err)
		}

		// Convert all decrypted keys to env vars
		for key, value := range decryptedData {
			envVars[strings.ToUpper(key)] = fmt.Sprintf("%v", value)
		}
	} else {
		// Handle plaintext multi-value data
		for key, value := range data {
			// Skip metadata fields
			if key == "ciphertext" || key == "value" {
				continue
			}
			envVars[strings.ToUpper(key)] = fmt.Sprintf("%v", value)
		}

		// Handle single value case
		if len(envVars) == 0 {
			if value, ok := data["value"]; ok {
				// Extract the base name from the path to use as env var name
				pathParts := strings.Split(vaultPath, "/")
				envVarName := strings.ToUpper(pathParts[len(pathParts)-1])
				envVars[envVarName] = fmt.Sprintf("%v", value)
			}
		}
	}

	if len(envVars) == 0 {
		return nil, fmt.Errorf("no valid secrets found at path %s", vaultPath)
	}

	return envVars, nil
}

// loadIndividualSecret loads a single secret using the old format
func (a *App) loadIndividualSecret(cfg *config.Config, secret *config.SecretEntry, kvMount, transitMount, encryptionKey string) (string, error) {
	// Get secret from KV
	data, err := a.vaultClient.KVGet(config.NonEmpty("", cfg.KV.Mount, kvMount), secret.KVPath)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", secret.Name, err)
	}

	// Handle different secret types
	if ciphertext, ok := data["ciphertext"].(string); ok && strings.HasPrefix(ciphertext, "vault:v") {
		// Single encrypted value
		encKeyForDecrypt := config.NonEmpty(encryptionKey, cfg.GetTransitKey(), "")
		if encKeyForDecrypt == "" {
			return "", fmt.Errorf("encryption key required for encrypted secret %s", secret.Name)
		}
		plaintext, err := a.vaultClient.TransitDecrypt(cfg.GetTransitMount(transitMount), encKeyForDecrypt, ciphertext)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt secret %s: %w", secret.Name, err)
		}
		return string(plaintext), nil
	} else if value, ok := data["value"].(string); ok {
		// Single plaintext value
		return value, nil
	} else if len(data) > 1 {
		// Multi-value secret - shouldn't be used in individual format
		return "", fmt.Errorf("secret %s contains multiple values, cannot determine which to use for %s", secret.Name, secret.EnvVar)
	} else {
		return "", fmt.Errorf("no valid data found for secret %s", secret.Name)
	}
}

// loadSingleKeyFromPath loads a single key from a Vault path
func (a *App) loadSingleKeyFromPath(cfg *config.Config, secret *config.SecretEntry, kvMount, transitMount, encryptionKey string) (string, error) {
	// Get all data from the Vault path
	data, err := a.vaultClient.KVGet(config.NonEmpty("", cfg.KV.Mount, kvMount), secret.Path)
	if err != nil {
		return "", fmt.Errorf("failed to get secrets from path %s: %w", secret.Path, err)
	}

	// Handle encrypted multi-value data
	if utils.IsEncryptedMultiValue(data) {
		encKeyForDecrypt := config.NonEmpty(encryptionKey, cfg.GetTransitKey(), "")
		if encKeyForDecrypt == "" {
			return "", fmt.Errorf("encryption key required for encrypted secrets at path %s", secret.Path)
		}

		decryptedData, err := utils.DecryptMultiValueData(data, a.vaultClient, cfg.GetTransitMount(transitMount), encKeyForDecrypt)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt secrets from path %s: %w", secret.Path, err)
		}

		// Extract the specific key
		value, ok := decryptedData[secret.Key]
		if !ok {
			return "", fmt.Errorf("key %q not found at path %s", secret.Key, secret.Path)
		}
		return fmt.Sprintf("%v", value), nil
	}

	// Handle plaintext data
	value, ok := data[secret.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found at path %s", secret.Key, secret.Path)
	}
	return fmt.Sprintf("%v", value), nil
}

// handleFileEntry processes a file entry from the config and saves it to disk
func (a *App) handleFileEntry(cfg *config.Config, secret *config.SecretEntry, kvMount, transitMount, encryptionKey string) error {
	// Get the secret value (same logic as loadSingleKeyFromPath but for files)
	secretValue, err := a.loadSingleKeyFromPath(cfg, secret, kvMount, transitMount, encryptionKey)
	if err != nil {
		return err
	}

	// Get the file configuration for this secret
	fileConfig, err := cfg.GetSecretFileConfig(secret)
	if err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Convert to utils.FileStorageOptions
	storageOpts := utils.FileStorageOptions{
		Path:      fileConfig.Path,
		Mode:      fileConfig.Mode,
		CreateDir: *fileConfig.CreateDir,
	}

	// Save the file
	return utils.SaveAsFileWithOptions(secretValue, storageOpts)
}

// handleDirEntry processes a directory entry from the config and saves all keys as individual files
func (a *App) handleDirEntry(cfg *config.Config, secret *config.SecretEntry, kvMount, transitMount, encryptionKey string) error {
	mount := config.NonEmpty("", cfg.KV.Mount, kvMount)

	if secret.Recursive {
		return a.handleDirEntryRecursive(cfg, secret, mount, transitMount, encryptionKey)
	}

	// Get all data from the Vault path
	data, err := a.vaultClient.KVGet(mount, secret.Path)
	if err != nil {
		return fmt.Errorf("failed to get secrets from path %s: %w", secret.Path, err)
	}

	return a.saveDirKeys(cfg, secret, secret.Path, "", data, transitMount, encryptionKey)
}

// handleDirEntryRecursive walks the Vault tree under secret.Path using KVList
// and saves every leaf secret into the target directory, preserving the sub-path structure.
func (a *App) handleDirEntryRecursive(cfg *config.Config, secret *config.SecretEntry, mount, transitMount, encryptionKey string) error {
	leafPaths, err := a.listRecursive(mount, secret.Path)
	if err != nil {
		return fmt.Errorf("failed to list secrets recursively under %s: %w", secret.Path, err)
	}

	if len(leafPaths) == 0 {
		return fmt.Errorf("no secrets found recursively under path %s", secret.Path)
	}

	for _, leafPath := range leafPaths {
		data, err := a.vaultClient.KVGet(mount, leafPath)
		if err != nil {
			return fmt.Errorf("failed to get secret at %s: %w", leafPath, err)
		}

		// Compute the relative sub-path from the base to build the directory structure
		relPath := strings.TrimPrefix(leafPath, secret.Path)
		relPath = strings.TrimPrefix(relPath, "/")

		if err := a.saveDirKeys(cfg, secret, leafPath, relPath, data, transitMount, encryptionKey); err != nil {
			return err
		}
	}

	return nil
}

// listRecursive walks Vault KVList from basePath and returns all leaf (non-directory) paths.
func (a *App) listRecursive(mount, basePath string) ([]string, error) {
	entries, err := a.vaultClient.KVList(mount, basePath)
	if err != nil {
		return nil, err
	}

	var leaves []string
	for _, entry := range entries {
		fullPath := basePath + "/" + strings.TrimSuffix(entry, "/")
		if strings.HasSuffix(entry, "/") {
			// It's a sub-directory — recurse
			subLeaves, err := a.listRecursive(mount, fullPath)
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, subLeaves...)
		} else {
			// It's a leaf secret
			leaves = append(leaves, fullPath)
		}
	}
	return leaves, nil
}

// saveDirKeys extracts keys from Vault data and saves each as a file.
// relPath is the relative sub-path (empty for non-recursive) used to create subdirectories.
func (a *App) saveDirKeys(cfg *config.Config, secret *config.SecretEntry, vaultPath, relPath string, data map[string]interface{}, transitMount, encryptionKey string) error {
	var keysToSave map[string]interface{}

	// Handle encrypted multi-value data
	if utils.IsEncryptedMultiValue(data) {
		encKeyForDecrypt := config.NonEmpty(encryptionKey, cfg.GetTransitKey(), "")
		if encKeyForDecrypt == "" {
			return fmt.Errorf("encryption key required for encrypted secrets at path %s", vaultPath)
		}

		decryptedData, err := utils.DecryptMultiValueData(data, a.vaultClient, cfg.GetTransitMount(transitMount), encKeyForDecrypt)
		if err != nil {
			return fmt.Errorf("failed to decrypt secrets from path %s: %w", vaultPath, err)
		}
		keysToSave = decryptedData
	} else {
		// Handle plaintext data
		keysToSave = make(map[string]interface{})
		for key, value := range data {
			// Skip common metadata keys but include everything else
			if key != "ciphertext" {
				keysToSave[key] = value
			}
		}

		// Handle single value case
		if len(keysToSave) == 0 {
			if value, ok := data["value"]; ok {
				// Use path name as filename
				pathParts := strings.Split(vaultPath, "/")
				keyName := pathParts[len(pathParts)-1]
				keysToSave[keyName] = value
			}
		}
	}

	if len(keysToSave) == 0 {
		return fmt.Errorf("no valid secrets found at path %s", vaultPath)
	}

	// Save each key as a file in the directory
	for keyName, value := range keysToSave {
		// Check if this key has a specific file configuration that overrides directory
		hasSpecificFileConfig := false
		for _, otherSecret := range cfg.Secrets {
			if otherSecret.Path == secret.Path && otherSecret.Key == keyName && otherSecret.IsFileEntry() {
				// This key has its own file config, skip it here
				hasSpecificFileConfig = true
				break
			}
		}

		if hasSpecificFileConfig {
			continue // Skip this key as it's handled by its own file configuration
		}

		// Build the file name including the sub-path for recursive entries
		fileName := keyName
		if relPath != "" {
			fileName = filepath.Join(relPath, keyName)
		}

		// Get directory file configuration for this key
		fileConfig, err := cfg.GetDirFileConfig(secret, fileName)
		if err != nil {
			return fmt.Errorf("invalid file path for key %s: %w", keyName, err)
		}

		// Convert to utils.FileStorageOptions
		storageOpts := utils.FileStorageOptions{
			Path:      fileConfig.Path,
			Mode:      fileConfig.Mode,
			CreateDir: *fileConfig.CreateDir,
		}

		// Save the file
		if err := utils.SaveAsFileWithOptions(fmt.Sprintf("%v", value), storageOpts); err != nil {
			return fmt.Errorf("failed to save key %s as file %s: %w", keyName, fileConfig.Path, err)
		}
	}

	return nil
}
