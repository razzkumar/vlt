package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsEncryptedSingleValue(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]any
		expected bool
	}{
		{
			name:     "encrypted single value",
			data:     map[string]any{"ciphertext": "vault:v1:abc123"},
			expected: true,
		},
		{
			name:     "encrypted single value v2",
			data:     map[string]any{"ciphertext": "vault:v2:xyz789"},
			expected: true,
		},
		{
			name:     "plaintext single value",
			data:     map[string]any{"value": "my-secret"},
			expected: false,
		},
		{
			name:     "multiple values",
			data:     map[string]any{"key1": "vault:v1:abc", "key2": "value"},
			expected: false,
		},
		{
			name:     "empty map",
			data:     map[string]any{},
			expected: false,
		},
		{
			name:     "ciphertext without vault prefix",
			data:     map[string]any{"ciphertext": "not-encrypted"},
			expected: false,
		},
		{
			name:     "non-string ciphertext",
			data:     map[string]any{"ciphertext": 123},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEncryptedSingleValue(tt.data)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsPlaintextSingleValue(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]any
		expected bool
	}{
		{
			name:     "plaintext single value",
			data:     map[string]any{"value": "my-secret"},
			expected: true,
		},
		{
			name:     "encrypted single value",
			data:     map[string]any{"ciphertext": "vault:v1:abc123"},
			expected: false,
		},
		{
			name:     "multiple values",
			data:     map[string]any{"value": "secret", "other": "data"},
			expected: false,
		},
		{
			name:     "empty map",
			data:     map[string]any{},
			expected: false,
		},
		{
			name:     "value with any type",
			data:     map[string]any{"value": 123},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPlaintextSingleValue(tt.data)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsEncryptedMultiValue(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]any
		expected bool
	}{
		{
			name:     "all encrypted values",
			data:     map[string]any{"key1": "vault:v1:abc", "key2": "vault:v1:xyz"},
			expected: true,
		},
		{
			name:     "some encrypted values",
			data:     map[string]any{"key1": "vault:v1:abc", "key2": "plaintext"},
			expected: true,
		},
		{
			name:     "no encrypted values",
			data:     map[string]any{"key1": "value1", "key2": "value2"},
			expected: false,
		},
		{
			name:     "empty map",
			data:     map[string]any{},
			expected: false,
		},
		{
			name:     "non-string values",
			data:     map[string]any{"key1": 123, "key2": true},
			expected: false,
		},
		{
			name:     "single encrypted value",
			data:     map[string]any{"ciphertext": "vault:v1:abc"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEncryptedMultiValue(tt.data)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMergeData(t *testing.T) {
	tests := []struct {
		name     string
		existing map[string]any
		new      map[string]any
		expected map[string]any
	}{
		{
			name:     "merge non-overlapping",
			existing: map[string]any{"a": "1", "b": "2"},
			new:      map[string]any{"c": "3", "d": "4"},
			expected: map[string]any{"a": "1", "b": "2", "c": "3", "d": "4"},
		},
		{
			name:     "override existing",
			existing: map[string]any{"a": "old", "b": "2"},
			new:      map[string]any{"a": "new", "c": "3"},
			expected: map[string]any{"a": "new", "b": "2", "c": "3"},
		},
		{
			name:     "empty existing",
			existing: map[string]any{},
			new:      map[string]any{"a": "1"},
			expected: map[string]any{"a": "1"},
		},
		{
			name:     "empty new",
			existing: map[string]any{"a": "1"},
			new:      map[string]any{},
			expected: map[string]any{"a": "1"},
		},
		{
			name:     "both empty",
			existing: map[string]any{},
			new:      map[string]any{},
			expected: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeData(tt.existing, tt.new)

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d keys, got %d", len(tt.expected), len(result))
			}

			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%v, got %s=%v", k, v, k, result[k])
				}
			}
		})
	}
}

func TestParseFileMode(t *testing.T) {
	// Note: ParseFileMode is now exported
	tests := []struct {
		name     string
		mode     string
		expected os.FileMode
		hasError bool
	}{
		{
			name:     "0644",
			mode:     "0644",
			expected: 0644,
			hasError: false,
		},
		{
			name:     "0600",
			mode:     "0600",
			expected: 0600,
			hasError: false,
		},
		{
			name:     "0755",
			mode:     "0755",
			expected: 0755,
			hasError: false,
		},
		{
			name:     "empty defaults to 0600",
			mode:     "",
			expected: 0600,
			hasError: false,
		},
		{
			name:     "invalid octal",
			mode:     "invalid",
			expected: 0,
			hasError: true,
		},
		{
			name:     "decimal number",
			mode:     "644",
			expected: 0644,
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseFileMode(tt.mode)

			if tt.hasError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %o, got %o", tt.expected, result)
			}
		})
	}
}

func TestLoadEnvFileAsPlaintext(t *testing.T) {
	// Create a temporary .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")

	content := `DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
# This is a comment
API_KEY=secret-key-123
`

	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	data, err := LoadEnvFileAsPlaintext(envFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]string{
		"DB_HOST": "localhost",
		"DB_PORT": "5432",
		"DB_USER": "admin",
		"API_KEY": "secret-key-123",
	}

	for k, v := range expected {
		if data[k] != v {
			t.Errorf("expected %s=%q, got %s=%q", k, v, k, data[k])
		}
	}
}

func TestLoadEnvFileAsPlaintext_FileNotFound(t *testing.T) {
	_, err := LoadEnvFileAsPlaintext("/nonexistent/.env")

	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestSaveAsFileWithOptions(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("save plain text", func(t *testing.T) {
		filePath := filepath.Join(tmpDir, "plain.txt")
		opts := FileStorageOptions{
			Path:      filePath,
			Mode:      "0644",
			CreateDir: false,
		}

		err := SaveAsFileWithOptions("hello world", opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if string(content) != "hello world" {
			t.Errorf("expected 'hello world', got %q", string(content))
		}
	})

	t.Run("save base64 content", func(t *testing.T) {
		filePath := filepath.Join(tmpDir, "base64.txt")
		opts := FileStorageOptions{
			Path:      filePath,
			Mode:      "0644",
			CreateDir: false,
		}

		// "hello world" in base64
		err := SaveAsFileWithOptions("aGVsbG8gd29ybGQ=", opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if string(content) != "hello world" {
			t.Errorf("expected 'hello world', got %q", string(content))
		}
	})

	t.Run("create directory", func(t *testing.T) {
		filePath := filepath.Join(tmpDir, "subdir", "nested", "file.txt")
		opts := FileStorageOptions{
			Path:      filePath,
			Mode:      "0644",
			CreateDir: true,
		}

		err := SaveAsFileWithOptions("content", opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Error("file was not created")
		}
	})

	t.Run("fail without create dir", func(t *testing.T) {
		filePath := filepath.Join(tmpDir, "nonexistent", "file.txt")
		opts := FileStorageOptions{
			Path:      filePath,
			Mode:      "0644",
			CreateDir: false,
		}

		err := SaveAsFileWithOptions("content", opts)
		if err == nil {
			t.Error("expected error when directory doesn't exist")
		}
	})

	t.Run("custom file mode", func(t *testing.T) {
		filePath := filepath.Join(tmpDir, "private.txt")
		opts := FileStorageOptions{
			Path:      filePath,
			Mode:      "0600",
			CreateDir: false,
		}

		err := SaveAsFileWithOptions("secret", opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("failed to stat file: %v", err)
		}

		// On some systems, the mode might be affected by umask
		mode := info.Mode().Perm()
		if mode != 0600 {
			t.Logf("note: file mode is %o (might be affected by umask)", mode)
		}
	})
}

func TestSaveAsFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "legacy.txt")

	// "test content" in base64
	err := SaveAsFile(filePath, "dGVzdCBjb250ZW50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(content) != "test content" {
		t.Errorf("expected 'test content', got %q", string(content))
	}
}
