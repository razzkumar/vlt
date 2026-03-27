package config

import (
	"os"
	"testing"
)

func TestGetVaultConfigFromEnv_TokenAuth(t *testing.T) {
	// Save original env and restore after test
	origAddr := os.Getenv("VAULT_ADDR")
	origToken := os.Getenv("VAULT_TOKEN")
	origAuthMethod := os.Getenv("VAULT_AUTH_METHOD")
	defer func() {
		os.Setenv("VAULT_ADDR", origAddr)
		os.Setenv("VAULT_TOKEN", origToken)
		os.Setenv("VAULT_AUTH_METHOD", origAuthMethod)
	}()

	os.Setenv("VAULT_ADDR", "https://vault.example.com")
	os.Setenv("VAULT_TOKEN", "test-token")
	os.Setenv("VAULT_AUTH_METHOD", "")

	cfg := GetVaultConfigFromEnv()

	if cfg.Addr != "https://vault.example.com" {
		t.Errorf("expected addr 'https://vault.example.com', got %q", cfg.Addr)
	}
	if cfg.Token != "test-token" {
		t.Errorf("expected token 'test-token', got %q", cfg.Token)
	}
	if cfg.Timeout != 15 {
		t.Errorf("expected default timeout 15, got %d", cfg.Timeout)
	}
}

func TestGetVaultConfigFromEnv_AppRoleAuth(t *testing.T) {
	origAddr := os.Getenv("VAULT_ADDR")
	origRoleID := os.Getenv("VAULT_ROLE_ID")
	origSecretID := os.Getenv("VAULT_SECRET_ID")
	origToken := os.Getenv("VAULT_TOKEN")
	defer func() {
		os.Setenv("VAULT_ADDR", origAddr)
		os.Setenv("VAULT_ROLE_ID", origRoleID)
		os.Setenv("VAULT_SECRET_ID", origSecretID)
		os.Setenv("VAULT_TOKEN", origToken)
	}()

	os.Setenv("VAULT_ADDR", "https://vault.example.com")
	os.Setenv("VAULT_TOKEN", "")
	os.Setenv("VAULT_ROLE_ID", "test-role-id")
	os.Setenv("VAULT_SECRET_ID", "test-secret-id")

	cfg := GetVaultConfigFromEnv()

	if cfg.RoleID != "test-role-id" {
		t.Errorf("expected role id 'test-role-id', got %q", cfg.RoleID)
	}
	if cfg.SecretID != "test-secret-id" {
		t.Errorf("expected secret id 'test-secret-id', got %q", cfg.SecretID)
	}
}

func TestGetVaultConfigFromEnv_GitHubAuth(t *testing.T) {
	origAddr := os.Getenv("VAULT_ADDR")
	origGitHubToken := os.Getenv("VAULT_GITHUB_TOKEN")
	origToken := os.Getenv("VAULT_TOKEN")
	defer func() {
		os.Setenv("VAULT_ADDR", origAddr)
		os.Setenv("VAULT_GITHUB_TOKEN", origGitHubToken)
		os.Setenv("VAULT_TOKEN", origToken)
	}()

	os.Setenv("VAULT_ADDR", "https://vault.example.com")
	os.Setenv("VAULT_TOKEN", "")
	os.Setenv("VAULT_GITHUB_TOKEN", "gh-test-token")

	cfg := GetVaultConfigFromEnv()

	if cfg.GitHubToken != "gh-test-token" {
		t.Errorf("expected github token 'gh-test-token', got %q", cfg.GitHubToken)
	}
}

func TestGetVaultConfigFromEnv_KubernetesAuth(t *testing.T) {
	origAddr := os.Getenv("VAULT_ADDR")
	origK8sRole := os.Getenv("VAULT_K8S_ROLE")
	origK8sJWTPath := os.Getenv("VAULT_K8S_JWT_PATH")
	origK8sAuthPath := os.Getenv("VAULT_K8S_AUTH_PATH")
	origToken := os.Getenv("VAULT_TOKEN")
	defer func() {
		os.Setenv("VAULT_ADDR", origAddr)
		os.Setenv("VAULT_K8S_ROLE", origK8sRole)
		os.Setenv("VAULT_K8S_JWT_PATH", origK8sJWTPath)
		os.Setenv("VAULT_K8S_AUTH_PATH", origK8sAuthPath)
		os.Setenv("VAULT_TOKEN", origToken)
	}()

	os.Setenv("VAULT_ADDR", "https://vault.example.com")
	os.Setenv("VAULT_TOKEN", "")
	os.Setenv("VAULT_K8S_ROLE", "my-app")
	os.Setenv("VAULT_K8S_JWT_PATH", "")
	os.Setenv("VAULT_K8S_AUTH_PATH", "")

	cfg := GetVaultConfigFromEnv()

	if cfg.K8sRole != "my-app" {
		t.Errorf("expected k8s role 'my-app', got %q", cfg.K8sRole)
	}
	// Check defaults
	if cfg.K8sJWTPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Errorf("expected default k8s jwt path, got %q", cfg.K8sJWTPath)
	}
	if cfg.K8sAuthPath != "kubernetes" {
		t.Errorf("expected default k8s auth path 'kubernetes', got %q", cfg.K8sAuthPath)
	}
}

func TestGetVaultConfigFromEnv_SkipVerify(t *testing.T) {
	tests := []struct {
		envValue string
		expected bool
	}{
		{"1", true},
		{"true", true},
		{"0", false},
		{"false", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run("skip_verify="+tt.envValue, func(t *testing.T) {
			origSkipVerify := os.Getenv("VAULT_SKIP_VERIFY")
			defer os.Setenv("VAULT_SKIP_VERIFY", origSkipVerify)

			os.Setenv("VAULT_SKIP_VERIFY", tt.envValue)

			cfg := GetVaultConfigFromEnv()

			if cfg.SkipVerify != tt.expected {
				t.Errorf("expected SkipVerify=%v for %q, got %v", tt.expected, tt.envValue, cfg.SkipVerify)
			}
		})
	}
}

func TestGetVaultConfigFromEnv_Timeout(t *testing.T) {
	origTimeout := os.Getenv("VAULT_TIMEOUT")
	defer os.Setenv("VAULT_TIMEOUT", origTimeout)

	os.Setenv("VAULT_TIMEOUT", "30")

	cfg := GetVaultConfigFromEnv()

	if cfg.Timeout != 30 {
		t.Errorf("expected timeout 30, got %d", cfg.Timeout)
	}
}

func TestVaultConfig_Validate_MissingAddr(t *testing.T) {
	cfg := &VaultConfig{
		Addr:  "",
		Token: "test-token",
	}

	err := cfg.Validate()

	if err != ErrMissingVaultAddr {
		t.Errorf("expected ErrMissingVaultAddr, got %v", err)
	}
}

func TestVaultConfig_Validate_MissingToken(t *testing.T) {
	cfg := &VaultConfig{
		Addr:       "https://vault.example.com",
		Token:      "",
		AuthMethod: "token",
	}

	err := cfg.Validate()

	if err != ErrMissingVaultToken {
		t.Errorf("expected ErrMissingVaultToken, got %v", err)
	}
}

func TestVaultConfig_Validate_AppRoleMissingRoleID(t *testing.T) {
	cfg := &VaultConfig{
		Addr:       "https://vault.example.com",
		AuthMethod: "approle",
		RoleID:     "",
		SecretID:   "secret",
	}

	err := cfg.Validate()

	if err == nil || err.Error() != "VAULT_ROLE_ID is required for AppRole auth" {
		t.Errorf("expected role id required error, got %v", err)
	}
}

func TestVaultConfig_Validate_AppRoleMissingSecretID(t *testing.T) {
	cfg := &VaultConfig{
		Addr:       "https://vault.example.com",
		AuthMethod: "approle",
		RoleID:     "role",
		SecretID:   "",
	}

	err := cfg.Validate()

	if err == nil || err.Error() != "VAULT_SECRET_ID is required for AppRole auth" {
		t.Errorf("expected secret id required error, got %v", err)
	}
}

func TestVaultConfig_Validate_GitHubMissingToken(t *testing.T) {
	cfg := &VaultConfig{
		Addr:        "https://vault.example.com",
		AuthMethod:  "github",
		GitHubToken: "",
	}

	err := cfg.Validate()

	if err == nil || err.Error() != "VAULT_GITHUB_TOKEN is required for GitHub auth" {
		t.Errorf("expected github token required error, got %v", err)
	}
}

func TestVaultConfig_Validate_KubernetesMissingRole(t *testing.T) {
	cfg := &VaultConfig{
		Addr:       "https://vault.example.com",
		AuthMethod: "kubernetes",
		K8sRole:    "",
	}

	err := cfg.Validate()

	if err == nil || err.Error() != "VAULT_K8S_ROLE is required for Kubernetes auth" {
		t.Errorf("expected k8s role required error, got %v", err)
	}
}

func TestVaultConfig_DetectAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *VaultConfig
		expected string
	}{
		{
			name:     "token auth",
			cfg:      &VaultConfig{Token: "test"},
			expected: "token",
		},
		{
			name:     "approle auth",
			cfg:      &VaultConfig{RoleID: "role", SecretID: "secret"},
			expected: "approle",
		},
		{
			name:     "github auth",
			cfg:      &VaultConfig{GitHubToken: "gh-token"},
			expected: "github",
		},
		{
			name:     "kubernetes auth",
			cfg:      &VaultConfig{K8sRole: "my-app"},
			expected: "kubernetes",
		},
		{
			name:     "default to token when nothing set",
			cfg:      &VaultConfig{},
			expected: "token",
		},
		{
			name:     "token takes priority over approle",
			cfg:      &VaultConfig{Token: "test", RoleID: "role", SecretID: "secret"},
			expected: "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cfg.DetectAuthMethod()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestIsTransitEnabled(t *testing.T) {
	tests := []struct {
		envValue string
		expected bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"enable", true},
		{"enabled", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"no", false},
		{"off", false},
		{"disable", false},
		{"disabled", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run("transit="+tt.envValue, func(t *testing.T) {
			origTransit := os.Getenv("TRANSIT")
			defer os.Setenv("TRANSIT", origTransit)

			os.Setenv("TRANSIT", tt.envValue)

			result := IsTransitEnabled()

			if result != tt.expected {
				t.Errorf("expected %v for %q, got %v", tt.expected, tt.envValue, result)
			}
		})
	}
}

func TestGetEncryptionKey(t *testing.T) {
	origEncryptionKey := os.Getenv("ENCRYPTION_KEY")
	origTransit := os.Getenv("TRANSIT")
	defer func() {
		os.Setenv("ENCRYPTION_KEY", origEncryptionKey)
		os.Setenv("TRANSIT", origTransit)
	}()

	t.Run("flag value takes priority", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", "env-key")
		os.Setenv("TRANSIT", "true")

		result := GetEncryptionKey("flag-key")

		if result != "flag-key" {
			t.Errorf("expected 'flag-key', got %q", result)
		}
	})

	t.Run("env value used when no flag", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", "env-key")
		os.Setenv("TRANSIT", "")

		result := GetEncryptionKey("")

		if result != "env-key" {
			t.Errorf("expected 'env-key', got %q", result)
		}
	})

	t.Run("default when transit enabled", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", "")
		os.Setenv("TRANSIT", "true")

		result := GetEncryptionKey("")

		if result != "app-secrets" {
			t.Errorf("expected 'app-secrets', got %q", result)
		}
	})

	t.Run("empty when nothing configured", func(t *testing.T) {
		os.Setenv("ENCRYPTION_KEY", "")
		os.Setenv("TRANSIT", "")

		result := GetEncryptionKey("")

		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})
}

func TestGetTransitMount(t *testing.T) {
	origTransitMount := os.Getenv("TRANSIT_MOUNT")
	defer os.Setenv("TRANSIT_MOUNT", origTransitMount)

	t.Run("flag value takes priority", func(t *testing.T) {
		os.Setenv("TRANSIT_MOUNT", "env-mount")

		result := GetTransitMount("flag-mount")

		if result != "flag-mount" {
			t.Errorf("expected 'flag-mount', got %q", result)
		}
	})

	t.Run("env value used when no flag", func(t *testing.T) {
		os.Setenv("TRANSIT_MOUNT", "env-mount")

		result := GetTransitMount("")

		if result != "env-mount" {
			t.Errorf("expected 'env-mount', got %q", result)
		}
	})

	t.Run("default transit mount", func(t *testing.T) {
		os.Setenv("TRANSIT_MOUNT", "")

		result := GetTransitMount("")

		if result != "transit" {
			t.Errorf("expected 'transit', got %q", result)
		}
	})
}

func TestShouldUseEncryption(t *testing.T) {
	origTransit := os.Getenv("TRANSIT")
	defer os.Setenv("TRANSIT", origTransit)

	t.Run("transit enabled", func(t *testing.T) {
		os.Setenv("TRANSIT", "true")

		result := ShouldUseEncryption("")

		if !result {
			t.Error("expected true when TRANSIT=true")
		}
	})

	t.Run("encryption key provided", func(t *testing.T) {
		os.Setenv("TRANSIT", "")

		result := ShouldUseEncryption("my-key")

		if !result {
			t.Error("expected true when encryption key provided")
		}
	})

	t.Run("transit explicitly disabled overrides key", func(t *testing.T) {
		os.Setenv("TRANSIT", "false")

		result := ShouldUseEncryption("my-key")

		if result {
			t.Error("expected false when TRANSIT=false even with key")
		}
	})

	t.Run("no encryption when nothing set", func(t *testing.T) {
		os.Setenv("TRANSIT", "")

		result := ShouldUseEncryption("")

		if result {
			t.Error("expected false when nothing configured")
		}
	})
}

func TestNonEmpty(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		expected string
	}{
		{
			name:     "first non-empty",
			values:   []string{"first", "second", "third"},
			expected: "first",
		},
		{
			name:     "skip empty values",
			values:   []string{"", "", "third"},
			expected: "third",
		},
		{
			name:     "all empty",
			values:   []string{"", "", ""},
			expected: "",
		},
		{
			name:     "middle value",
			values:   []string{"", "second", "third"},
			expected: "second",
		},
		{
			name:     "single value",
			values:   []string{"only"},
			expected: "only",
		},
		{
			name:     "no values",
			values:   []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NonEmpty(tt.values...)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSecretEntry_IsPathBased(t *testing.T) {
	tests := []struct {
		name     string
		entry    SecretEntry
		expected bool
	}{
		{
			name:     "path set",
			entry:    SecretEntry{Path: "secret/data/app"},
			expected: true,
		},
		{
			name:     "path not set",
			entry:    SecretEntry{KVPath: "app/config", EnvVar: "CONFIG"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsPathBased()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSecretEntry_IsIndividual(t *testing.T) {
	tests := []struct {
		name     string
		entry    SecretEntry
		expected bool
	}{
		{
			name:     "individual format",
			entry:    SecretEntry{KVPath: "app/config", EnvVar: "CONFIG"},
			expected: true,
		},
		{
			name:     "missing env var",
			entry:    SecretEntry{KVPath: "app/config"},
			expected: false,
		},
		{
			name:     "missing kv path",
			entry:    SecretEntry{EnvVar: "CONFIG"},
			expected: false,
		},
		{
			name:     "path based",
			entry:    SecretEntry{Path: "secret/data/app"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsIndividual()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSecretEntry_IsPathAllKeys(t *testing.T) {
	tests := []struct {
		name     string
		entry    SecretEntry
		expected bool
	}{
		{
			name:     "all keys from path",
			entry:    SecretEntry{Path: "secret/data/app"},
			expected: true,
		},
		{
			name:     "single key from path",
			entry:    SecretEntry{Path: "secret/data/app", Key: "api_key"},
			expected: false,
		},
		{
			name:     "no path",
			entry:    SecretEntry{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsPathAllKeys()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSecretEntry_IsPathSingleKey(t *testing.T) {
	tests := []struct {
		name     string
		entry    SecretEntry
		expected bool
	}{
		{
			name:     "single key from path",
			entry:    SecretEntry{Path: "secret/data/app", Key: "api_key"},
			expected: true,
		},
		{
			name:     "all keys from path",
			entry:    SecretEntry{Path: "secret/data/app"},
			expected: false,
		},
		{
			name:     "no path",
			entry:    SecretEntry{Key: "api_key"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsPathSingleKey()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSecretEntry_IsFileEntry(t *testing.T) {
	tests := []struct {
		name     string
		entry    SecretEntry
		expected bool
	}{
		{
			name:     "file entry",
			entry:    SecretEntry{Path: "secret/data/app", Key: "cert", File: &SecretFileConfig{Path: "/tmp/cert.pem"}},
			expected: true,
		},
		{
			name:     "no file config",
			entry:    SecretEntry{Path: "secret/data/app", Key: "cert"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsFileEntry()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSecretEntry_IsDirEntry(t *testing.T) {
	tests := []struct {
		name     string
		entry    SecretEntry
		expected bool
	}{
		{
			name:     "dir entry",
			entry:    SecretEntry{Path: "secret/data/certs", Dir: "/tmp/certs"},
			expected: true,
		},
		{
			name:     "no dir config",
			entry:    SecretEntry{Path: "secret/data/certs"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsDirEntry()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSecretEntry_GetEnvKeyName(t *testing.T) {
	tests := []struct {
		name     string
		entry    SecretEntry
		expected string
	}{
		{
			name:     "env_key specified",
			entry:    SecretEntry{Key: "api_key", EnvKey: "MY_API_KEY"},
			expected: "MY_API_KEY",
		},
		{
			name:     "key uppercase",
			entry:    SecretEntry{Key: "api_key"},
			expected: "API_KEY",
		},
		{
			name:     "no key",
			entry:    SecretEntry{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.GetEnvKeyName()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestConfig_GetTransitMount(t *testing.T) {
	t.Run("config transit mount", func(t *testing.T) {
		cfg := &Config{
			Transit: &struct {
				Mount string `yaml:"mount"`
				Key   string `yaml:"key"`
			}{
				Mount: "custom-transit",
			},
		}

		result := cfg.GetTransitMount("default-transit")

		if result != "custom-transit" {
			t.Errorf("expected 'custom-transit', got %q", result)
		}
	})

	t.Run("default when no config", func(t *testing.T) {
		cfg := &Config{}

		result := cfg.GetTransitMount("default-transit")

		if result != "default-transit" {
			t.Errorf("expected 'default-transit', got %q", result)
		}
	})
}

func TestConfig_GetTransitKey(t *testing.T) {
	t.Run("config transit key", func(t *testing.T) {
		cfg := &Config{
			Transit: &struct {
				Mount string `yaml:"mount"`
				Key   string `yaml:"key"`
			}{
				Key: "my-key",
			},
		}

		result := cfg.GetTransitKey()

		if result != "my-key" {
			t.Errorf("expected 'my-key', got %q", result)
		}
	})

	t.Run("empty when no config", func(t *testing.T) {
		cfg := &Config{}

		result := cfg.GetTransitKey()

		if result != "" {
			t.Errorf("expected empty string, got %q", result)
		}
	})
}

func TestConfig_GetFileStorageConfig(t *testing.T) {
	t.Run("returns defaults when nil", func(t *testing.T) {
		cfg := &Config{}

		result := cfg.GetFileStorageConfig()

		if result.OutputDir != "." {
			t.Errorf("expected output dir '.', got %q", result.OutputDir)
		}
		if result.DefaultMode != "0600" {
			t.Errorf("expected default mode '0600', got %q", result.DefaultMode)
		}
		if result.CreateDirs == nil || !*result.CreateDirs {
			t.Error("expected CreateDirs to be true")
		}
	})

	t.Run("applies defaults to partial config", func(t *testing.T) {
		cfg := &Config{
			Files: &FileStorageConfig{
				OutputDir: "/custom/dir",
			},
		}

		result := cfg.GetFileStorageConfig()

		if result.OutputDir != "/custom/dir" {
			t.Errorf("expected output dir '/custom/dir', got %q", result.OutputDir)
		}
		if result.DefaultMode != "0600" {
			t.Errorf("expected default mode '0600', got %q", result.DefaultMode)
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with path-based secrets",
			cfg: &Config{
				Secrets: []SecretEntry{
					{Path: "secret/data/app"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with individual secrets",
			cfg: &Config{
				Secrets: []SecretEntry{
					{KVPath: "app/config", EnvVar: "CONFIG"},
				},
			},
			wantErr: false,
		},
		{
			name:    "empty secrets",
			cfg:     &Config{},
			wantErr: true,
			errMsg:  "no secrets defined",
		},
		{
			name: "invalid secret entry",
			cfg: &Config{
				Secrets: []SecretEntry{
					{Path: "secret/data/app", KVPath: "app/config"},
				},
			},
			wantErr: true,
			errMsg:  "cannot mix",
		},
		{
			name: "invalid file mode in files config",
			cfg: &Config{
				Files: &FileStorageConfig{
					DefaultMode: "invalid",
				},
				Secrets: []SecretEntry{
					{Path: "secret/data/app"},
				},
			},
			wantErr: true,
			errMsg:  "files.default_mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSecretEntry_Validate(t *testing.T) {
	tests := []struct {
		name    string
		entry   SecretEntry
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid path-based all keys",
			entry:   SecretEntry{Path: "secret/data/app"},
			wantErr: false,
		},
		{
			name:    "valid path-based single key",
			entry:   SecretEntry{Path: "secret/data/app", Key: "api_key"},
			wantErr: false,
		},
		{
			name:    "valid path-based with env_key",
			entry:   SecretEntry{Path: "secret/data/app", Key: "api_key", EnvKey: "MY_API_KEY"},
			wantErr: false,
		},
		{
			name:    "valid individual format",
			entry:   SecretEntry{KVPath: "app/config", EnvVar: "CONFIG"},
			wantErr: false,
		},
		{
			name: "valid file entry",
			entry: SecretEntry{
				Path: "secret/data/app",
				Key:  "cert",
				File: &SecretFileConfig{Path: "/tmp/cert.pem"},
			},
			wantErr: false,
		},
		{
			name:    "valid dir entry",
			entry:   SecretEntry{Path: "secret/data/certs", Dir: "/tmp/certs"},
			wantErr: false,
		},
		{
			name:    "mix old and new format",
			entry:   SecretEntry{Path: "secret/data/app", KVPath: "app/config"},
			wantErr: true,
			errMsg:  "cannot mix",
		},
		{
			name:    "neither format specified",
			entry:   SecretEntry{},
			wantErr: true,
			errMsg:  "either 'path' or 'kv_path'",
		},
		{
			name:    "old format missing kv_path",
			entry:   SecretEntry{EnvVar: "CONFIG"},
			wantErr: true,
			errMsg:  "kv_path is required",
		},
		{
			name:    "old format missing env_var",
			entry:   SecretEntry{KVPath: "app/config"},
			wantErr: true,
			errMsg:  "env_var is required",
		},
		{
			name:    "env_key without key",
			entry:   SecretEntry{Path: "secret/data/app", EnvKey: "MY_KEY"},
			wantErr: true,
			errMsg:  "env_key requires 'key'",
		},
		{
			name: "file without key",
			entry: SecretEntry{
				Path: "secret/data/app",
				File: &SecretFileConfig{Path: "/tmp/cert.pem"},
			},
			wantErr: true,
			errMsg:  "file output requires 'key'",
		},
		{
			name: "file and dir both specified",
			entry: SecretEntry{
				Path: "secret/data/app",
				Key:  "cert",
				File: &SecretFileConfig{Path: "/tmp/cert.pem"},
				Dir:  "/tmp/certs",
			},
			wantErr: true,
			errMsg:  "cannot specify both 'file' and 'dir'",
		},
		{
			name: "invalid file mode",
			entry: SecretEntry{
				Path: "secret/data/app",
				Key:  "cert",
				File: &SecretFileConfig{Path: "/tmp/cert.pem", Mode: "999"},
			},
			wantErr: true,
			errMsg:  "file.mode",
		},
		{
			name:    "valid recursive dir entry",
			entry:   SecretEntry{Path: "creds/gpg", Dir: "/tmp/gpg-keys", Recursive: true},
			wantErr: false,
		},
		{
			name:    "recursive without dir",
			entry:   SecretEntry{Path: "creds/gpg", Recursive: true},
			wantErr: true,
			errMsg:  "'recursive' requires 'dir'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateFileMode(t *testing.T) {
	tests := []struct {
		mode    string
		wantErr bool
	}{
		{"0644", false},
		{"0755", false},
		{"0600", false},
		{"644", false},
		{"755", false},
		{"0777", false},
		{"1755", false}, // with sticky bit
		{"", true},
		{"invalid", true},
		{"0999", true},     // invalid octal
		{"08", true},       // too short
		{"01234567", true}, // too long
	}

	for _, tt := range tests {
		t.Run("mode="+tt.mode, func(t *testing.T) {
			err := validateFileMode(tt.mode)

			if tt.wantErr && err == nil {
				t.Errorf("expected error for mode %q", tt.mode)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for mode %q: %v", tt.mode, err)
			}
		})
	}
}

// containsString is a helper to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
