package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	content := `version: 1
vault:
  addr: https://vault.example.com
  namespace: my-namespace
kv:
  mount: secret
secrets:
  - path: app/config
  - path: app/db
    key: password
    env_key: DB_PASSWORD
`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	cfg, err := app.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
	if cfg.Vault.Addr != "https://vault.example.com" {
		t.Errorf("expected vault addr 'https://vault.example.com', got %q", cfg.Vault.Addr)
	}
	if cfg.Vault.Namespace != "my-namespace" {
		t.Errorf("expected namespace 'my-namespace', got %q", cfg.Vault.Namespace)
	}
	if cfg.KV.Mount != "secret" {
		t.Errorf("expected kv mount 'secret', got %q", cfg.KV.Mount)
	}
	if len(cfg.Secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(cfg.Secrets))
	}
}

func TestLoadConfig_WithTransit(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	content := `version: 1
vault:
  addr: https://vault.example.com
transit:
  mount: custom-transit
  key: my-key
kv:
  mount: secret
secrets:
  - path: app/config
`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	cfg, err := app.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Transit == nil {
		t.Fatal("expected transit config to be set")
	}
	if cfg.Transit.Mount != "custom-transit" {
		t.Errorf("expected transit mount 'custom-transit', got %q", cfg.Transit.Mount)
	}
	if cfg.Transit.Key != "my-key" {
		t.Errorf("expected transit key 'my-key', got %q", cfg.Transit.Key)
	}
}

func TestLoadConfig_WithFileStorage(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	content := `version: 1
vault:
  addr: https://vault.example.com
kv:
  mount: secret
files:
  output_dir: /tmp/secrets
  default_mode: "0600"
  create_dirs: true
secrets:
  - path: app/certs
    key: tls.crt
    file:
      path: /etc/ssl/cert.pem
      mode: "0644"
`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	cfg, err := app.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Files == nil {
		t.Fatal("expected files config to be set")
	}
	if cfg.Files.OutputDir != "/tmp/secrets" {
		t.Errorf("expected output_dir '/tmp/secrets', got %q", cfg.Files.OutputDir)
	}
	if cfg.Files.DefaultMode != "0600" {
		t.Errorf("expected default_mode '0600', got %q", cfg.Files.DefaultMode)
	}

	if len(cfg.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(cfg.Secrets))
	}
	secret := cfg.Secrets[0]
	if secret.File == nil {
		t.Fatal("expected file config in secret")
	}
	if secret.File.Path != "/etc/ssl/cert.pem" {
		t.Errorf("expected file path '/etc/ssl/cert.pem', got %q", secret.File.Path)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	_, err := app.LoadConfig("/nonexistent/config.yaml")

	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	content := `invalid: yaml: content: [unclosed
`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	_, err := app.LoadConfig(configFile)

	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestGenerateEnvFile(t *testing.T) {
	// Create config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	outputFile := filepath.Join(tmpDir, "output.env")

	configContent := `version: 1
kv:
  mount: kv
secrets:
  - path: app/config
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"db_host": "localhost",
		"db_port": "5432",
	})

	app := NewWithClient(mock)

	// Capture stdout (GenerateEnvFile prints a message)
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.GenerateEnvFile(configFile, outputFile, "")

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output file was created
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	outputStr := string(content)
	if outputStr == "" {
		t.Error("expected non-empty output file")
	}
}

func TestLoadSecretsFromConfig_PathAllKeys(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `version: 1
kv:
  mount: kv
secrets:
  - path: app/config
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"api_key":    "secret-key",
		"api_secret": "secret-value",
	})

	app := NewWithClient(mock)
	cfg, _ := app.LoadConfig(configFile)

	envVars, err := app.loadSecretsFromConfig(cfg, "kv", "transit", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Keys should be uppercased
	if envVars["API_KEY"] != "secret-key" {
		t.Errorf("expected API_KEY='secret-key', got %q", envVars["API_KEY"])
	}
	if envVars["API_SECRET"] != "secret-value" {
		t.Errorf("expected API_SECRET='secret-value', got %q", envVars["API_SECRET"])
	}
}

func TestLoadSecretsFromConfig_PathSingleKey(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `version: 1
kv:
  mount: kv
secrets:
  - path: app/config
    key: api_key
    env_key: MY_API_KEY
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"api_key":    "secret-key",
		"api_secret": "secret-value",
	})

	app := NewWithClient(mock)
	cfg, _ := app.LoadConfig(configFile)

	envVars, err := app.loadSecretsFromConfig(cfg, "kv", "transit", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the specified key should be loaded with custom env var name
	if envVars["MY_API_KEY"] != "secret-key" {
		t.Errorf("expected MY_API_KEY='secret-key', got %q", envVars["MY_API_KEY"])
	}
	if _, exists := envVars["API_SECRET"]; exists {
		t.Error("did not expect API_SECRET in output")
	}
}

func TestLoadSecretsFromConfig_IndividualFormat(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `version: 1
kv:
  mount: kv
secrets:
  - name: my-secret
    kv_path: app/secret
    env_var: SECRET_VALUE
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/secret", map[string]interface{}{
		"value": "my-secret-value",
	})

	app := NewWithClient(mock)
	cfg, _ := app.LoadConfig(configFile)

	envVars, err := app.loadSecretsFromConfig(cfg, "kv", "transit", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if envVars["SECRET_VALUE"] != "my-secret-value" {
		t.Errorf("expected SECRET_VALUE='my-secret-value', got %q", envVars["SECRET_VALUE"])
	}
}

func TestLoadSecretsFromConfig_EncryptedValues(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `version: 1
kv:
  mount: kv
transit:
  mount: transit
  key: my-key
secrets:
  - path: app/encrypted
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	mock := vault.NewMockClient()
	// Set up encrypted multi-value data
	mock.SetSecret("kv", "app/encrypted", map[string]interface{}{
		"api_key": "vault:v1:c2VjcmV0LWtleQ==", // base64 of "secret-key"
	})

	app := NewWithClient(mock)
	cfg, _ := app.LoadConfig(configFile)

	envVars, err := app.loadSecretsFromConfig(cfg, "kv", "transit", "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if envVars["API_KEY"] != "secret-key" {
		t.Errorf("expected API_KEY='secret-key', got %q", envVars["API_KEY"])
	}
}

func TestGetFromConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `version: 1
kv:
  mount: kv
secrets:
  - path: app/config
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"key": "value",
	})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.GetFromConfigWithOptions(configFile, &GetFromConfigOptions{
		EncryptionKey: "",
		OutputJSON:    false,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if output == "" {
		t.Error("expected non-empty output")
	}
}
