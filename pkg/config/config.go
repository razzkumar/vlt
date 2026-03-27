package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds the application configuration
type Config struct {
	Version int `yaml:"version"`
	Vault   struct {
		Addr       string `yaml:"addr"`
		Namespace  string `yaml:"namespace"`
		SkipVerify bool   `yaml:"skip_verify"`
		CACert     string `yaml:"ca_cert"`
	} `yaml:"vault"`
	Transit *struct {
		Mount string `yaml:"mount"`
		Key   string `yaml:"key"`
	} `yaml:"transit,omitempty"`
	KV struct {
		Mount string `yaml:"mount"`
	} `yaml:"kv"`
	Files   *FileStorageConfig `yaml:"files,omitempty"`
	Secrets []SecretEntry      `yaml:"secrets"`
}

// FileStorageConfig holds global file storage configuration
type FileStorageConfig struct {
	// OutputDir specifies the default directory where files should be saved (default: current directory)
	OutputDir string `yaml:"output_dir,omitempty"`
	// DefaultMode sets the default file permissions (octal, e.g., 0600)
	DefaultMode string `yaml:"default_mode,omitempty"`
	// CreateDirs controls whether to create directories if they don't exist by default (defaults to true)
	CreateDirs *bool `yaml:"create_dirs,omitempty"`
}

// SecretFileConfig holds file configuration for a specific secret
type SecretFileConfig struct {
	// Path specifies the full path where this file should be saved
	// Supports tilde expansion (~) and can be absolute or relative
	// If relative and no global output_dir, uses current directory
	Path string `yaml:"path,omitempty"`
	// Mode sets file permissions (octal, e.g., 0600) - defaults to global default or 0600
	Mode string `yaml:"mode,omitempty"`
	// CreateDir controls whether to create the directory for this file - defaults to global setting or true
	CreateDir *bool `yaml:"create_dir,omitempty"`
}

// SecretEntry represents a secret configuration entry
// Supports multiple formats:
// 1. Old format: individual secret mapping (name, kv_path, env_var)
// 2. New format: all keys from path (path only)
// 3. Selective format: single key from path (path + key)
// 4. Mapped format: single key from path with custom env name (path + key + env_key)
// 5. File format: save key as file with file configuration (path + key + file)
// 6. Directory format: save all keys as files in directory (path + dir)
type SecretEntry struct {
	// Old format - individual secret mapping
	Name     string `yaml:"name,omitempty"`
	KVPath   string `yaml:"kv_path,omitempty"`  // path under kv mount
	EnvVar   string `yaml:"env_var,omitempty"`  // environment variable name
	Required bool   `yaml:"required,omitempty"` // fail if secret not found

	// New formats - path-based
	Path   string `yaml:"path,omitempty"`    // vault path
	Key    string `yaml:"key,omitempty"`     // specific key to extract (optional)
	EnvKey string `yaml:"env_key,omitempty"` // custom env var name (optional, requires key)

	// File configuration - when this key should be saved as a file
	File *SecretFileConfig `yaml:"file,omitempty"`

	// Directory configuration - when all keys should be saved as individual files
	Dir string `yaml:"dir,omitempty"` // directory path to save all keys as individual files
}

// VaultConfig holds Vault client configuration
type VaultConfig struct {
	Addr       string
	Token      string
	Namespace  string
	CACert     string
	SkipVerify bool
	Timeout    int // seconds

	// Authentication methods
	AuthMethod string // auto-detected or explicitly set

	// AppRole auth
	RoleID   string
	SecretID string

	// GitHub auth
	GitHubToken string

	// Kubernetes auth
	K8sRole     string
	K8sJWTPath  string // defaults to /var/run/secrets/kubernetes.io/serviceaccount/token
	K8sAuthPath string // defaults to kubernetes
}

// GetVaultConfigFromEnv creates VaultConfig from environment variables
func GetVaultConfigFromEnv() *VaultConfig {
	cfg := &VaultConfig{
		Addr:      os.Getenv("VAULT_ADDR"),
		Token:     os.Getenv("VAULT_TOKEN"),
		Namespace: os.Getenv("VAULT_NAMESPACE"),
		CACert:    os.Getenv("VAULT_CACERT"),
		Timeout:   15, // default timeout

		// Auth method (explicit or auto-detected)
		AuthMethod: strings.ToLower(os.Getenv("VAULT_AUTH_METHOD")),

		// AppRole auth
		RoleID:   os.Getenv("VAULT_ROLE_ID"),
		SecretID: os.Getenv("VAULT_SECRET_ID"),

		// GitHub auth
		GitHubToken: os.Getenv("VAULT_GITHUB_TOKEN"),

		// Kubernetes auth
		K8sRole:     os.Getenv("VAULT_K8S_ROLE"),
		K8sJWTPath:  os.Getenv("VAULT_K8S_JWT_PATH"),
		K8sAuthPath: os.Getenv("VAULT_K8S_AUTH_PATH"),
	}

	if skip := os.Getenv("VAULT_SKIP_VERIFY"); skip == "1" || skip == "true" {
		cfg.SkipVerify = true
	}

	if timeout := os.Getenv("VAULT_TIMEOUT"); timeout != "" {
		if t, err := strconv.Atoi(timeout); err == nil && t > 0 {
			cfg.Timeout = t
		}
	}

	// Set defaults for Kubernetes auth
	if cfg.K8sJWTPath == "" {
		cfg.K8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	if cfg.K8sAuthPath == "" {
		cfg.K8sAuthPath = "kubernetes"
	}

	return cfg
}

// VaultConfigOverrides holds optional overrides for VaultConfig
// Empty strings are ignored (env value used instead)
type VaultConfigOverrides struct {
	Addr        string
	Token       string
	Namespace   string
	AuthMethod  string
	RoleID      string
	SecretID    string
	GitHubToken string
	K8sRole     string
}

// GetVaultConfigWithOverrides creates VaultConfig from environment variables with optional overrides
// This allows CLI flags to take precedence without mutating environment variables
func GetVaultConfigWithOverrides(overrides *VaultConfigOverrides) *VaultConfig {
	cfg := GetVaultConfigFromEnv()

	if overrides == nil {
		return cfg
	}

	// Apply overrides (non-empty values take precedence)
	if overrides.Addr != "" {
		cfg.Addr = overrides.Addr
	}
	if overrides.Token != "" {
		cfg.Token = overrides.Token
	}
	if overrides.Namespace != "" {
		cfg.Namespace = overrides.Namespace
	}
	if overrides.AuthMethod != "" {
		cfg.AuthMethod = strings.ToLower(overrides.AuthMethod)
	}
	if overrides.RoleID != "" {
		cfg.RoleID = overrides.RoleID
	}
	if overrides.SecretID != "" {
		cfg.SecretID = overrides.SecretID
	}
	if overrides.GitHubToken != "" {
		cfg.GitHubToken = overrides.GitHubToken
	}
	if overrides.K8sRole != "" {
		cfg.K8sRole = overrides.K8sRole
	}

	return cfg
}

// Validate checks if the configuration is valid
func (c *VaultConfig) Validate() error {
	if c.Addr == "" {
		return ErrMissingVaultAddr
	}

	// Auto-detect auth method if not explicitly set
	if c.AuthMethod == "" {
		c.AuthMethod = c.DetectAuthMethod()
	}

	// Validate based on auth method
	switch c.AuthMethod {
	case "token":
		if c.Token == "" {
			return ErrMissingVaultToken
		}
	case "approle":
		if c.RoleID == "" {
			return fmt.Errorf("VAULT_ROLE_ID is required for AppRole auth")
		}
		if c.SecretID == "" {
			return fmt.Errorf("VAULT_SECRET_ID is required for AppRole auth")
		}
	case "github":
		if c.GitHubToken == "" {
			return fmt.Errorf("VAULT_GITHUB_TOKEN is required for GitHub auth")
		}
	case "kubernetes":
		if c.K8sRole == "" {
			return fmt.Errorf("VAULT_K8S_ROLE is required for Kubernetes auth")
		}
	default:
		return fmt.Errorf("unsupported or auto-detected auth method: %s. Supported: token, approle, github, kubernetes", c.AuthMethod)
	}

	return nil
}

// DetectAuthMethod auto-detects the auth method based on available credentials
func (c *VaultConfig) DetectAuthMethod() string {
	// Priority order for auto-detection
	if c.Token != "" {
		return "token"
	}
	if c.RoleID != "" && c.SecretID != "" {
		return "approle"
	}
	if c.GitHubToken != "" {
		return "github"
	}
	if c.K8sRole != "" {
		return "kubernetes"
	}
	// Default to token if nothing else detected
	return "token"
}

// GetEncryptionKey returns the encryption key from environment or parameter
// If TRANSIT is enabled and no key is configured, returns default "app-secrets"
func GetEncryptionKey(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	envKey := os.Getenv("ENCRYPTION_KEY")
	if envKey != "" {
		return envKey
	}

	// If TRANSIT is enabled but no encryption key configured, use default
	if IsTransitEnabled() {
		return "app-secrets"
	}

	return ""
}

// IsTransitEnabled returns true if transit encryption should be enabled
// Checks TRANSIT environment variable for true/false or 1/0 values
func IsTransitEnabled() bool {
	transit := strings.ToLower(os.Getenv("TRANSIT"))
	switch transit {
	case "true", "1", "yes", "on", "enable", "enabled":
		return true
	case "false", "0", "no", "off", "disable", "disabled":
		return false
	default:
		// If TRANSIT is not set or invalid, don't enable by default
		return false
	}
}

// GetTransitMount returns the transit mount path with default fallback
// If TRANSIT is enabled and no mount is configured, returns default "transit"
func GetTransitMount(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}

	envMount := os.Getenv("TRANSIT_MOUNT")
	if envMount != "" {
		return envMount
	}

	// Default to "transit" (this is already the default in CLI flags, but good to be explicit)
	return "transit"
}

// ShouldUseEncryption determines if encryption should be used based on encryption key and TRANSIT env var
func ShouldUseEncryption(encryptionKey string) bool {
	// If TRANSIT is explicitly enabled, use encryption
	if IsTransitEnabled() {
		return true
	}

	// If encryption key is provided and TRANSIT is not explicitly disabled, use encryption
	if encryptionKey != "" {
		// Check if TRANSIT is explicitly disabled
		transit := strings.ToLower(os.Getenv("TRANSIT"))
		if transit == "false" || transit == "0" || transit == "no" || transit == "off" || transit == "disable" || transit == "disabled" {
			return false
		}
		return true
	}

	// Default: no encryption
	return false
}

// NonEmpty returns the first non-empty string from the provided values
func NonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// IsPathBased returns true if this secret entry uses the new path-based format
func (s *SecretEntry) IsPathBased() bool {
	return s.Path != ""
}

// IsIndividual returns true if this secret entry uses the old individual format
func (s *SecretEntry) IsIndividual() bool {
	return s.KVPath != "" && s.EnvVar != ""
}

// IsPathAllKeys returns true if this loads all keys from the path
func (s *SecretEntry) IsPathAllKeys() bool {
	return s.Path != "" && s.Key == ""
}

// IsPathSingleKey returns true if this loads a single key from the path
func (s *SecretEntry) IsPathSingleKey() bool {
	return s.Path != "" && s.Key != ""
}

// IsFileEntry returns true if this secret should be saved as a file
func (s *SecretEntry) IsFileEntry() bool {
	return s.File != nil
}

// IsDirEntry returns true if all keys from this path should be saved as individual files in a directory
func (s *SecretEntry) IsDirEntry() bool {
	return s.Dir != ""
}

// RequiresKey returns true if this entry must have a key specified
func (s *SecretEntry) RequiresKey() bool {
	return s.IsFileEntry() // File entries always need a specific key
}

// HasFileOrDirConfig returns true if this entry has file or directory configuration
func (s *SecretEntry) HasFileOrDirConfig() bool {
	return s.IsFileEntry() || s.IsDirEntry()
}

// GetEnvKeyName returns the environment variable name for this secret
func (s *SecretEntry) GetEnvKeyName() string {
	if s.EnvKey != "" {
		return s.EnvKey
	}
	if s.Key != "" {
		return strings.ToUpper(s.Key)
	}
	return ""
}

// GetTransitMount returns the transit mount path, with fallback
func (c *Config) GetTransitMount(defaultMount string) string {
	if c.Transit != nil && c.Transit.Mount != "" {
		return c.Transit.Mount
	}
	return defaultMount
}

// GetTransitKey returns the transit encryption key
func (c *Config) GetTransitKey() string {
	if c.Transit != nil {
		return c.Transit.Key
	}
	return ""
}

// GetFileStorageConfig returns file storage configuration with defaults
func (c *Config) GetFileStorageConfig() *FileStorageConfig {
	if c.Files == nil {
		defaultCreateDirs := true
		c.Files = &FileStorageConfig{
			OutputDir:   ".",
			DefaultMode: "0600",
			CreateDirs:  &defaultCreateDirs,
		}
		return c.Files
	}

	// Apply defaults to existing config
	if c.Files.OutputDir == "" {
		c.Files.OutputDir = "."
	}
	if c.Files.DefaultMode == "" {
		c.Files.DefaultMode = "0600"
	}
	if c.Files.CreateDirs == nil {
		defaultCreateDirs := true
		c.Files.CreateDirs = &defaultCreateDirs
	}

	return c.Files
}

// GetSecretFileConfig returns the resolved file configuration for a secret entry
func (c *Config) GetSecretFileConfig(secretEntry *SecretEntry) (SecretFileConfig, error) {
	fileStorage := c.GetFileStorageConfig()

	if secretEntry.File == nil {
		// Return default config using key as filename
		filename := secretEntry.Key
		if filename == "" {
			filename = "secret_file"
		}
		createDir := true
		if fileStorage.CreateDirs != nil {
			createDir = *fileStorage.CreateDirs
		}
		return SecretFileConfig{
			Path:      filepath.Join(fileStorage.OutputDir, filename),
			Mode:      fileStorage.DefaultMode,
			CreateDir: &createDir,
		}, nil
	}

	// Start with the secret's file config
	result := *secretEntry.File

	// Apply defaults
	if result.Mode == "" {
		result.Mode = fileStorage.DefaultMode
	}

	if result.CreateDir == nil {
		result.CreateDir = fileStorage.CreateDirs
	}

	// Resolve path
	if result.Path == "" {
		// Use key as filename with global output dir
		filename := secretEntry.Key
		if filename == "" {
			filename = "secret_file"
		}
		result.Path = filepath.Join(fileStorage.OutputDir, filename)
	} else {
		// Expand tilde and resolve relative paths with traversal protection
		resolvedPath, err := expandPath(result.Path, fileStorage.OutputDir)
		if err != nil {
			return SecretFileConfig{}, err
		}
		result.Path = resolvedPath
	}

	return result, nil
}

// GetDirFileConfig returns the file configuration for saving a key as a file in the specified directory
func (c *Config) GetDirFileConfig(secretEntry *SecretEntry, keyName string) (SecretFileConfig, error) {
	fileStorage := c.GetFileStorageConfig()

	// Expand the directory path with traversal protection
	dirPath, err := expandPath(secretEntry.Dir, fileStorage.OutputDir)
	if err != nil {
		return SecretFileConfig{}, err
	}

	// Create file path using key name as filename
	filePath := filepath.Join(dirPath, keyName)

	createDir := true
	if fileStorage.CreateDirs != nil {
		createDir = *fileStorage.CreateDirs
	}

	return SecretFileConfig{
		Path:      filePath,
		Mode:      fileStorage.DefaultMode,
		CreateDir: &createDir,
	}, nil
}

// Validate validates the Config structure
func (c *Config) Validate() error {
	var errs []string

	// Check for at least one secret entry
	if len(c.Secrets) == 0 {
		errs = append(errs, "no secrets defined in config")
	}

	// Validate each secret entry
	for i, entry := range c.Secrets {
		if err := entry.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("secret[%d]: %v", i, err))
		}
	}

	// Validate file storage config if present
	if c.Files != nil {
		if c.Files.DefaultMode != "" {
			if err := validateFileMode(c.Files.DefaultMode); err != nil {
				errs = append(errs, fmt.Sprintf("files.default_mode: %v", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}

// Validate validates a SecretEntry
func (s *SecretEntry) Validate() error {
	// Check that either old or new format is used, not both
	hasOldFormat := s.KVPath != "" || s.EnvVar != ""
	hasNewFormat := s.Path != ""

	if hasOldFormat && hasNewFormat {
		return fmt.Errorf("cannot mix old format (kv_path/env_var) with new format (path)")
	}

	if !hasOldFormat && !hasNewFormat {
		return fmt.Errorf("either 'path' or 'kv_path'+'env_var' is required")
	}

	// Validate old format
	if hasOldFormat {
		if s.KVPath == "" {
			return fmt.Errorf("kv_path is required when using old format")
		}
		if s.EnvVar == "" {
			return fmt.Errorf("env_var is required when using old format")
		}
	}

	// Validate new format
	if hasNewFormat {
		// env_key requires key
		if s.EnvKey != "" && s.Key == "" {
			return fmt.Errorf("env_key requires 'key' to be specified")
		}

		// file requires key
		if s.File != nil && s.Key == "" {
			return fmt.Errorf("file output requires 'key' to be specified")
		}

		// dir and file are mutually exclusive
		if s.File != nil && s.Dir != "" {
			return fmt.Errorf("cannot specify both 'file' and 'dir'")
		}

		// Validate file mode if specified
		if s.File != nil && s.File.Mode != "" {
			if err := validateFileMode(s.File.Mode); err != nil {
				return fmt.Errorf("file.mode: %v", err)
			}
		}
	}

	return nil
}

// validateFileMode checks if a file mode string is valid octal
func validateFileMode(mode string) error {
	// Remove leading 0 if present
	cleanMode := strings.TrimPrefix(mode, "0")
	if cleanMode == "" {
		return fmt.Errorf("invalid file mode: empty")
	}

	// Check each character is valid octal
	for _, c := range cleanMode {
		if c < '0' || c > '7' {
			return fmt.Errorf("invalid octal digit in mode: %c", c)
		}
	}

	// Check length (should be 3 or 4 digits after removing leading 0)
	if len(cleanMode) < 3 || len(cleanMode) > 4 {
		return fmt.Errorf("invalid file mode length: %s (expected 3-4 octal digits)", mode)
	}

	return nil
}

// expandPath expands ~ and resolves relative paths, with path traversal protection
func expandPath(path, outputDir string) (string, error) {
	// Expand tilde
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(homeDir, path[2:])
		}
	}

	// Track whether the path was already absolute (including tilde-expanded)
	wasAbsolute := filepath.IsAbs(path)

	// If still relative and we have an output dir, make it relative to output dir
	if !wasAbsolute && outputDir != "" {
		path = filepath.Join(outputDir, path)
	}

	// Clean the path to resolve any ".." or "." components
	path = filepath.Clean(path)

	// Only enforce containment for paths derived from outputDir (i.e. originally relative).
	// Absolute paths (including tilde-expanded) are explicit user choices — don't restrict them.
	if !wasAbsolute && outputDir != "" {
		absOutputDir, err := filepath.Abs(outputDir)
		if err != nil {
			return "", fmt.Errorf("failed to resolve output directory: %w", err)
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("failed to resolve path: %w", err)
		}
		if !strings.HasPrefix(absPath, absOutputDir+string(filepath.Separator)) && absPath != absOutputDir {
			return "", fmt.Errorf("path traversal detected: resolved path %s is outside output directory %s", absPath, absOutputDir)
		}
	}

	return path, nil
}
