package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestAppPut_SingleValuePlaintext(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Capture stdout (Put prints a confirmation message)
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Put(&PutOptions{
		KVMount: "kv",
		KVPath:  "app/secret",
		Value:   "my-secret-value",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify KVPut was called
	if len(mock.KVPutCalls) != 1 {
		t.Fatalf("expected 1 KVPut call, got %d", len(mock.KVPutCalls))
	}

	call := mock.KVPutCalls[0]
	if call.Mount != "kv" {
		t.Errorf("expected mount 'kv', got %q", call.Mount)
	}
	if call.Path != "app/secret" {
		t.Errorf("expected path 'app/secret', got %q", call.Path)
	}

	// Check data structure
	value, ok := call.Data["value"].(string)
	if !ok {
		t.Fatal("expected 'value' key in data")
	}
	if value != "my-secret-value" {
		t.Errorf("expected 'my-secret-value', got %q", value)
	}
}

func TestAppPut_SingleValueEncrypted(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Put(&PutOptions{
		KVMount:       "kv",
		KVPath:        "app/secret",
		TransitMount:  "transit",
		EncryptionKey: "my-key",
		Value:         "secret-value",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify TransitEncrypt was called
	if len(mock.TransitEncryptCalls) != 1 {
		t.Fatalf("expected 1 TransitEncrypt call, got %d", len(mock.TransitEncryptCalls))
	}

	// Verify data is encrypted
	call := mock.KVPutCalls[0]
	ciphertext, ok := call.Data["ciphertext"].(string)
	if !ok {
		t.Fatal("expected 'ciphertext' key in data")
	}
	if ciphertext == "" {
		t.Error("expected non-empty ciphertext")
	}
}

func TestAppPut_KeyValuePair(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Put(&PutOptions{
		KVMount: "kv",
		KVPath:  "app/config",
		Key:     "api_key",
		Value:   "secret-api-key",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify data structure
	call := mock.KVPutCalls[0]
	value, ok := call.Data["api_key"].(string)
	if !ok {
		t.Fatal("expected 'api_key' key in data")
	}
	if value != "secret-api-key" {
		t.Errorf("expected 'secret-api-key', got %q", value)
	}
}

func TestAppPut_MergeWithExisting(t *testing.T) {
	mock := vault.NewMockClient()
	// Pre-populate existing secret
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"db_host": "localhost",
		"db_port": "5432",
	})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	// Add a new key
	err := app.Put(&PutOptions{
		KVMount: "kv",
		KVPath:  "app/config",
		Key:     "db_user",
		Value:   "admin",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify merged data
	call := mock.KVPutCalls[0]
	if call.Data["db_host"] != "localhost" {
		t.Errorf("expected existing 'db_host' to be preserved")
	}
	if call.Data["db_port"] != "5432" {
		t.Errorf("expected existing 'db_port' to be preserved")
	}
	if call.Data["db_user"] != "admin" {
		t.Errorf("expected new 'db_user' to be added")
	}
}

func TestAppPut_FromEnvFile(t *testing.T) {
	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `DB_HOST=localhost
DB_PORT=5432
API_KEY=secret123
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

	err := app.Put(&PutOptions{
		KVMount: "kv",
		KVPath:  "app/config",
		FromEnv: envFile,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify data
	call := mock.KVPutCalls[0]
	if call.Data["DB_HOST"] != "localhost" {
		t.Errorf("expected DB_HOST='localhost', got %v", call.Data["DB_HOST"])
	}
	if call.Data["DB_PORT"] != "5432" {
		t.Errorf("expected DB_PORT='5432', got %v", call.Data["DB_PORT"])
	}
	if call.Data["API_KEY"] != "secret123" {
		t.Errorf("expected API_KEY='secret123', got %v", call.Data["API_KEY"])
	}
}

func TestAppPut_FromEnvFileEncrypted(t *testing.T) {
	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `SECRET_KEY=my-secret
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

	err := app.Put(&PutOptions{
		KVMount:       "kv",
		KVPath:        "app/secrets",
		TransitMount:  "transit",
		EncryptionKey: "my-key",
		FromEnv:       envFile,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify TransitEncrypt was called
	if len(mock.TransitEncryptCalls) != 1 {
		t.Errorf("expected 1 TransitEncrypt call, got %d", len(mock.TransitEncryptCalls))
	}

	// Verify encrypted data
	call := mock.KVPutCalls[0]
	ciphertext, ok := call.Data["SECRET_KEY"].(string)
	if !ok {
		t.Fatal("expected 'SECRET_KEY' in data")
	}
	if ciphertext == "my-secret" {
		t.Error("expected encrypted value, got plaintext")
	}
}

func TestAppPut_FromFile(t *testing.T) {
	// Create a temporary file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "cert.pem")

	content := "-----BEGIN CERTIFICATE-----\ntest-certificate\n-----END CERTIFICATE-----"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Put(&PutOptions{
		KVMount:  "kv",
		KVPath:   "app/certs",
		FromFile: testFile,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify data (file content should be base64 encoded)
	call := mock.KVPutCalls[0]
	value, ok := call.Data["cert.pem"].(string)
	if !ok {
		t.Fatal("expected 'cert.pem' key in data")
	}
	if value == "" {
		t.Error("expected non-empty base64 content")
	}
}

func TestAppPut_VaultError(t *testing.T) {
	mock := vault.NewMockClient()
	mock.KVPutErr = os.ErrPermission

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Put(&PutOptions{
		KVMount: "kv",
		KVPath:  "app/secret",
		Value:   "test",
	})

	w.Close()
	os.Stdout = oldStdout

	if err == nil {
		t.Error("expected error from vault")
	}
}

func TestAppPut_EmptyValue(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Create a pipe for stdin to avoid blocking
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Close() // Close immediately to simulate empty input

	// Capture stdout
	oldStdout := os.Stdout
	_, stdoutW, _ := os.Pipe()
	os.Stdout = stdoutW

	err := app.Put(&PutOptions{
		KVMount: "kv",
		KVPath:  "app/secret",
		Value:   "", // Empty value, will try to read from stdin
	})

	stdoutW.Close()
	os.Stdout = oldStdout
	os.Stdin = oldStdin

	if err == nil {
		t.Error("expected error for empty value")
	}
}

func TestAppPut_EncryptedKeyValuePair(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Put(&PutOptions{
		KVMount:       "kv",
		KVPath:        "app/config",
		TransitMount:  "transit",
		EncryptionKey: "my-key",
		Key:           "api_key",
		Value:         "super-secret",
	})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify TransitEncrypt was called
	if len(mock.TransitEncryptCalls) != 1 {
		t.Fatalf("expected 1 TransitEncrypt call, got %d", len(mock.TransitEncryptCalls))
	}

	// Verify the key contains encrypted value
	call := mock.KVPutCalls[0]
	ciphertext, ok := call.Data["api_key"].(string)
	if !ok {
		t.Fatal("expected 'api_key' key in data")
	}
	if ciphertext == "super-secret" {
		t.Error("expected encrypted value, got plaintext")
	}
}
