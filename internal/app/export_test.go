package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestAppExport(t *testing.T) {
	tests := []struct {
		name      string
		opts      *ExportOptions
		setupMock func(*vault.MockClient)
		wantErr   bool
		errMsg    string
		checkJSON func(t *testing.T, data map[string]interface{})
		checkEnv  func(t *testing.T, content string)
	}{
		{
			name: "export as JSON",
			opts: &ExportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "json",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "myapp/config", map[string]interface{}{
					"API_KEY": "test-api-key",
					"DB_HOST": "localhost",
				})
			},
			wantErr: false,
			checkJSON: func(t *testing.T, data map[string]interface{}) {
				if data["API_KEY"] != "test-api-key" {
					t.Errorf("expected API_KEY=test-api-key, got %v", data["API_KEY"])
				}
				if data["DB_HOST"] != "localhost" {
					t.Errorf("expected DB_HOST=localhost, got %v", data["DB_HOST"])
				}
			},
		},
		{
			name: "export as env",
			opts: &ExportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "env",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "myapp/config", map[string]interface{}{
					"API_KEY": "test-api-key",
				})
			},
			wantErr: false,
			checkEnv: func(t *testing.T, content string) {
				if !strings.Contains(content, "API_KEY=\"test-api-key\"") {
					t.Errorf("expected API_KEY in env format, got %s", content)
				}
			},
		},
		{
			name: "export with decryption",
			opts: &ExportOptions{
				KVMount:       "secret",
				Path:          "myapp/config",
				Format:        "json",
				EncryptionKey: "mykey",
				TransitMount:  "transit",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "myapp/config", map[string]interface{}{
					"API_KEY": "vault:v1:dGVzdC1hcGkta2V5", // base64 of "test-api-key"
				})
			},
			wantErr: false,
			checkJSON: func(t *testing.T, data map[string]interface{}) {
				if data["API_KEY"] != "test-api-key" {
					t.Errorf("expected decrypted API_KEY=test-api-key, got %v", data["API_KEY"])
				}
			},
		},
		{
			name: "missing path",
			opts: &ExportOptions{
				KVMount: "secret",
				Format:  "json",
			},
			setupMock: func(m *vault.MockClient) {},
			wantErr:   true,
			errMsg:    "path is required",
		},
		{
			name: "vault error",
			opts: &ExportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "json",
			},
			setupMock: func(m *vault.MockClient) {
				m.KVGetErr = errors.New("permission denied")
			},
			wantErr: true,
			errMsg:  "failed to get secret",
		},
		{
			name: "unsupported format",
			opts: &ExportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "xml",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "myapp/config", map[string]interface{}{
					"key": "value",
				})
			},
			wantErr: true,
			errMsg:  "unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := vault.NewMockClient()
			tt.setupMock(mockClient)

			app := NewWithClient(mockClient)

			// Create temp file for output
			tmpDir := t.TempDir()
			outputFile := filepath.Join(tmpDir, "output")
			tt.opts.Output = outputFile

			err := app.Export(tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Read output file
			content, err := os.ReadFile(outputFile)
			if err != nil {
				t.Fatalf("failed to read output file: %v", err)
			}

			if tt.checkJSON != nil {
				var data map[string]interface{}
				if err := json.Unmarshal(content, &data); err != nil {
					t.Fatalf("failed to parse JSON output: %v", err)
				}
				tt.checkJSON(t, data)
			}

			if tt.checkEnv != nil {
				tt.checkEnv(t, string(content))
			}
		})
	}
}
