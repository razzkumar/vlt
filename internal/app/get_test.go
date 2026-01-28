package app

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestAppGet_PlaintextSingleValue(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/secret", map[string]interface{}{"value": "my-secret-value"})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Get(&GetOptions{
		KVMount: "kv",
		KVPath:  "app/secret",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if output != "my-secret-value\n" {
		t.Errorf("expected 'my-secret-value\\n', got %q", output)
	}

	// Verify KVGet was called
	if len(mock.KVGetCalls) != 1 {
		t.Errorf("expected 1 KVGet call, got %d", len(mock.KVGetCalls))
	}
}

func TestAppGet_EncryptedSingleValue(t *testing.T) {
	mock := vault.NewMockClient()
	// Pre-encrypt "my-secret" to vault:v1:bXktc2VjcmV0 (base64 of "my-secret")
	mock.SetSecret("kv", "app/encrypted", map[string]interface{}{"ciphertext": "vault:v1:bXktc2VjcmV0"})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Get(&GetOptions{
		KVMount:       "kv",
		KVPath:        "app/encrypted",
		TransitMount:  "transit",
		EncryptionKey: "my-key",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if output != "my-secret\n" {
		t.Errorf("expected 'my-secret\\n', got %q", output)
	}

	// Verify TransitDecrypt was called
	if len(mock.TransitDecryptCalls) != 1 {
		t.Errorf("expected 1 TransitDecrypt call, got %d", len(mock.TransitDecryptCalls))
	}
}

func TestAppGet_MultiValuePlaintext(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"db_host": "localhost",
		"db_port": "5432",
	})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Get(&GetOptions{
		KVMount: "kv",
		KVPath:  "app/config",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Output is in env format
	if output == "" {
		t.Error("expected non-empty output")
	}
}

func TestAppGet_SpecificKey(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"db_host": "localhost",
		"db_port": "5432",
		"db_user": "admin",
	})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Get(&GetOptions{
		KVMount: "kv",
		KVPath:  "app/config",
		Key:     "db_host",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if output != "localhost\n" {
		t.Errorf("expected 'localhost\\n', got %q", output)
	}
}

func TestAppGet_KeyNotFound(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"db_host": "localhost",
	})

	app := NewWithClient(mock)

	err := app.Get(&GetOptions{
		KVMount: "kv",
		KVPath:  "app/config",
		Key:     "nonexistent",
	})

	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestAppGet_EncryptedMultiValue(t *testing.T) {
	mock := vault.NewMockClient()
	// Set up encrypted multi-value data
	mock.SetSecret("kv", "app/encrypted-config", map[string]interface{}{
		"api_key":    "vault:v1:c2VjcmV0LWtleQ==", // base64 of "secret-key"
		"db_pass":    "vault:v1:ZGItcGFzc3dvcmQ=", // base64 of "db-password"
		"plain_text": "not-encrypted",
	})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Get(&GetOptions{
		KVMount:       "kv",
		KVPath:        "app/encrypted-config",
		TransitMount:  "transit",
		EncryptionKey: "my-key",
		Key:           "api_key",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if output != "secret-key\n" {
		t.Errorf("expected 'secret-key\\n', got %q", output)
	}
}

func TestAppGet_MissingEncryptionKey(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/encrypted", map[string]interface{}{"ciphertext": "vault:v1:abc123"})

	app := NewWithClient(mock)

	// Clear TRANSIT and ENCRYPTION_KEY env vars
	origTransit := os.Getenv("TRANSIT")
	origEncKey := os.Getenv("ENCRYPTION_KEY")
	defer func() {
		os.Setenv("TRANSIT", origTransit)
		os.Setenv("ENCRYPTION_KEY", origEncKey)
	}()
	os.Setenv("TRANSIT", "")
	os.Setenv("ENCRYPTION_KEY", "")

	err := app.Get(&GetOptions{
		KVMount:       "kv",
		KVPath:        "app/encrypted",
		TransitMount:  "transit",
		EncryptionKey: "",
	})

	if err == nil {
		t.Error("expected error when encryption key is required but not provided")
	}
}

func TestAppGet_VaultError(t *testing.T) {
	mock := vault.NewMockClient()
	mock.KVGetErr = os.ErrNotExist

	app := NewWithClient(mock)

	err := app.Get(&GetOptions{
		KVMount: "kv",
		KVPath:  "app/nonexistent",
	})

	if err == nil {
		t.Error("expected error from vault")
	}
}

func TestAppGet_JSONOutput(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/config", map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})

	app := NewWithClient(mock)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.Get(&GetOptions{
		KVMount:    "kv",
		KVPath:     "app/config",
		OutputJSON: true,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should contain JSON formatting
	if output == "" {
		t.Error("expected non-empty JSON output")
	}
}
