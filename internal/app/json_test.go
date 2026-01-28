package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestJSON_PlaintextOutput(t *testing.T) {
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

	// Clear TRANSIT env var
	origTransit := os.Getenv("TRANSIT")
	defer os.Setenv("TRANSIT", origTransit)
	os.Setenv("TRANSIT", "")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.JSON(&JSONOptions{
		EnvFile: envFile,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify JSON contains expected keys
	if !strings.Contains(output, "DB_HOST") {
		t.Error("expected output to contain 'DB_HOST'")
	}
	if !strings.Contains(output, "localhost") {
		t.Error("expected output to contain 'localhost'")
	}
	if !strings.Contains(output, "{") {
		t.Error("expected JSON output")
	}
}

func TestJSON_EncryptedOutput(t *testing.T) {
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
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.JSON(&JSONOptions{
		TransitMount:  "transit",
		EncryptionKey: "my-key",
		EnvFile:       envFile,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains encrypted value (vault:v1: prefix)
	if !strings.Contains(output, "vault:v1:") {
		t.Error("expected output to contain encrypted value")
	}

	// TransitEncrypt should have been called
	if len(mock.TransitEncryptCalls) != 1 {
		t.Errorf("expected 1 TransitEncrypt call, got %d", len(mock.TransitEncryptCalls))
	}
}

func TestJSON_DefaultEnvFile(t *testing.T) {
	// Create a .env file in a temp dir
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `KEY=value
`
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Change to tmpDir
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Clear TRANSIT env var
	origTransit := os.Getenv("TRANSIT")
	defer os.Setenv("TRANSIT", origTransit)
	os.Setenv("TRANSIT", "")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Don't specify EnvFile, should default to .env
	err := app.JSON(&JSONOptions{})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "KEY") {
		t.Error("expected output to contain 'KEY'")
	}
}

func TestJSON_FileNotFound(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Clear TRANSIT env var
	origTransit := os.Getenv("TRANSIT")
	defer os.Setenv("TRANSIT", origTransit)
	os.Setenv("TRANSIT", "")

	err := app.JSON(&JSONOptions{
		EnvFile: "/nonexistent/.env",
	})

	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestJSON_TransitEnabled(t *testing.T) {
	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `SECRET=value
`
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Set TRANSIT=true
	origTransit := os.Getenv("TRANSIT")
	defer os.Setenv("TRANSIT", origTransit)
	os.Setenv("TRANSIT", "true")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.JSON(&JSONOptions{
		TransitMount: "transit",
		EnvFile:      envFile,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should contain encrypted value
	if !strings.Contains(output, "vault:v1:") {
		t.Error("expected output to contain encrypted value when TRANSIT=true")
	}
}

func TestJSON_MultipleValues(t *testing.T) {
	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `VAR1=value1
VAR2=value2
VAR3=value3
`
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Clear TRANSIT env var
	origTransit := os.Getenv("TRANSIT")
	defer os.Setenv("TRANSIT", origTransit)
	os.Setenv("TRANSIT", "")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := app.JSON(&JSONOptions{
		EnvFile: envFile,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify all values are present
	if !strings.Contains(output, "VAR1") {
		t.Error("expected output to contain 'VAR1'")
	}
	if !strings.Contains(output, "VAR2") {
		t.Error("expected output to contain 'VAR2'")
	}
	if !strings.Contains(output, "VAR3") {
		t.Error("expected output to contain 'VAR3'")
	}
}
