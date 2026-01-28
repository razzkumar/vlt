package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestLoadInlineSecrets(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/api-key", map[string]interface{}{"value": "secret-api-key"})
	mock.SetSecret("kv", "app/db-pass", map[string]interface{}{"value": "db-password"})

	app := NewWithClient(mock)

	secrets, err := app.loadInlineSecrets(
		[]string{"API_KEY=app/api-key", "DB_PASS=app/db-pass"},
		"kv",
		"transit",
		"",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if secrets["API_KEY"] != "secret-api-key" {
		t.Errorf("expected API_KEY='secret-api-key', got %q", secrets["API_KEY"])
	}

	if secrets["DB_PASS"] != "db-password" {
		t.Errorf("expected DB_PASS='db-password', got %q", secrets["DB_PASS"])
	}
}

func TestLoadInlineSecrets_InvalidFormat(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	_, err := app.loadInlineSecrets(
		[]string{"INVALID_FORMAT"},
		"kv",
		"transit",
		"",
	)

	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestLoadInlineSecrets_EmptyEnvVar(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	_, err := app.loadInlineSecrets(
		[]string{"=app/secret"},
		"kv",
		"transit",
		"",
	)

	if err == nil {
		t.Error("expected error for empty env var")
	}
}

func TestLoadInlineSecrets_EmptyPath(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	_, err := app.loadInlineSecrets(
		[]string{"API_KEY="},
		"kv",
		"transit",
		"",
	)

	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestLoadInlineSecrets_EncryptedValue(t *testing.T) {
	mock := vault.NewMockClient()
	// Set up encrypted secret
	mock.SetSecret("kv", "app/encrypted", map[string]interface{}{"ciphertext": "vault:v1:c2VjcmV0LXZhbHVl"})

	app := NewWithClient(mock)

	secrets, err := app.loadInlineSecrets(
		[]string{"SECRET=app/encrypted"},
		"kv",
		"transit",
		"my-key",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if secrets["SECRET"] != "secret-value" {
		t.Errorf("expected 'secret-value', got %q", secrets["SECRET"])
	}
}

func TestLoadInlineSecrets_EncryptedWithoutKey(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/encrypted", map[string]interface{}{"ciphertext": "vault:v1:abc123"})

	app := NewWithClient(mock)

	_, err := app.loadInlineSecrets(
		[]string{"SECRET=app/encrypted"},
		"kv",
		"transit",
		"", // No encryption key
	)

	if err == nil {
		t.Error("expected error when encryption key is required")
	}
}

func TestLoadInlineSecrets_MultiValueError(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/multi", map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})

	app := NewWithClient(mock)

	_, err := app.loadInlineSecrets(
		[]string{"SECRET=app/multi"},
		"kv",
		"transit",
		"",
	)

	if err == nil {
		t.Error("expected error for multi-value secret")
	}
}

func TestLoadInlineSecrets_SingleKeySecret(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/single", map[string]interface{}{
		"only_key": "only_value",
	})

	app := NewWithClient(mock)

	secrets, err := app.loadInlineSecrets(
		[]string{"SECRET=app/single"},
		"kv",
		"transit",
		"",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if secrets["SECRET"] != "only_value" {
		t.Errorf("expected 'only_value', got %q", secrets["SECRET"])
	}
}

func TestRun_DryRun(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/secret", map[string]interface{}{"value": "test-secret"})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Run(&RunOptions{
		KVMount:       "kv",
		InjectSecrets: []string{"SECRET=app/secret"},
		DryRun:        true,
		Command:       "echo",
		Args:          []string{"hello"},
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_WithEnvFile(t *testing.T) {
	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `ENV_VAR=from-file
`
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Run(&RunOptions{
		EnvFile: envFile,
		DryRun:  true,
		Command: "echo",
		Args:    []string{"hello"},
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_PreserveEnv(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Set an env var to preserve
	os.Setenv("TEST_PRESERVE_VAR", "preserved-value")
	defer os.Unsetenv("TEST_PRESERVE_VAR")

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Run(&RunOptions{
		PreserveEnv: true,
		DryRun:      true,
		Command:     "echo",
		Args:        []string{"hello"},
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_VaultError(t *testing.T) {
	mock := vault.NewMockClient()
	mock.KVGetErr = os.ErrNotExist

	app := NewWithClient(mock)

	err := app.Run(&RunOptions{
		KVMount:       "kv",
		InjectSecrets: []string{"SECRET=app/nonexistent"},
		DryRun:        true,
		Command:       "echo",
		Args:          []string{"hello"},
	})

	if err == nil {
		t.Error("expected error from vault")
	}
}

func TestLoadEnvFileForRun(t *testing.T) {
	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `DB_HOST=localhost
DB_PORT=5432
`
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	envVars, err := app.loadEnvFileForRun(envFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if envVars["DB_HOST"] != "localhost" {
		t.Errorf("expected DB_HOST='localhost', got %q", envVars["DB_HOST"])
	}
	if envVars["DB_PORT"] != "5432" {
		t.Errorf("expected DB_PORT='5432', got %q", envVars["DB_PORT"])
	}
}

func TestLoadEnvFileForRun_FileNotFound(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	_, err := app.loadEnvFileForRun("/nonexistent/.env")

	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
