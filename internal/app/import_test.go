package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestAppImport(t *testing.T) {
	tests := []struct {
		name        string
		opts        *ImportOptions
		fileContent string
		setupMock   func(*vault.MockClient)
		wantErr     bool
		errMsg      string
		checkStore  func(t *testing.T, m *vault.MockClient)
	}{
		{
			name: "import JSON file",
			opts: &ImportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "json",
			},
			fileContent: `{"API_KEY": "test-api-key", "DB_HOST": "localhost"}`,
			setupMock:   func(m *vault.MockClient) {},
			wantErr:     false,
			checkStore: func(t *testing.T, m *vault.MockClient) {
				if len(m.KVPutCalls) != 1 {
					t.Errorf("expected 1 KVPut call, got %d", len(m.KVPutCalls))
					return
				}
				call := m.KVPutCalls[0]
				if call.Data["API_KEY"] != "test-api-key" {
					t.Errorf("expected API_KEY=test-api-key, got %v", call.Data["API_KEY"])
				}
			},
		},
		{
			name: "import env file",
			opts: &ImportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "env",
			},
			fileContent: "API_KEY=test-api-key\nDB_HOST=localhost",
			setupMock:   func(m *vault.MockClient) {},
			wantErr:     false,
			checkStore: func(t *testing.T, m *vault.MockClient) {
				if len(m.KVPutCalls) != 1 {
					t.Errorf("expected 1 KVPut call, got %d", len(m.KVPutCalls))
					return
				}
				call := m.KVPutCalls[0]
				if call.Data["API_KEY"] != "test-api-key" {
					t.Errorf("expected API_KEY=test-api-key, got %v", call.Data["API_KEY"])
				}
			},
		},
		{
			name: "import with encryption",
			opts: &ImportOptions{
				KVMount:       "secret",
				Path:          "myapp/config",
				Format:        "json",
				EncryptionKey: "mykey",
				TransitMount:  "transit",
			},
			fileContent: `{"API_KEY": "test-api-key"}`,
			setupMock:   func(m *vault.MockClient) {},
			wantErr:     false,
			checkStore: func(t *testing.T, m *vault.MockClient) {
				if len(m.TransitEncryptCalls) != 1 {
					t.Errorf("expected 1 TransitEncrypt call, got %d", len(m.TransitEncryptCalls))
				}
				call := m.KVPutCalls[0]
				if !strings.HasPrefix(call.Data["API_KEY"].(string), "vault:v1:") {
					t.Errorf("expected encrypted value, got %v", call.Data["API_KEY"])
				}
			},
		},
		{
			name: "import with merge",
			opts: &ImportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "json",
				Merge:   true,
			},
			fileContent: `{"NEW_KEY": "new-value"}`,
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "myapp/config", map[string]interface{}{
					"EXISTING_KEY": "existing-value",
				})
			},
			wantErr: false,
			checkStore: func(t *testing.T, m *vault.MockClient) {
				call := m.KVPutCalls[0]
				if call.Data["EXISTING_KEY"] != "existing-value" {
					t.Errorf("expected EXISTING_KEY=existing-value, got %v", call.Data["EXISTING_KEY"])
				}
				if call.Data["NEW_KEY"] != "new-value" {
					t.Errorf("expected NEW_KEY=new-value, got %v", call.Data["NEW_KEY"])
				}
			},
		},
		{
			name: "auto-detect JSON format",
			opts: &ImportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				// Format not specified, file is .json
			},
			fileContent: `{"API_KEY": "test-api-key"}`,
			setupMock:   func(m *vault.MockClient) {},
			wantErr:     false,
			checkStore: func(t *testing.T, m *vault.MockClient) {
				call := m.KVPutCalls[0]
				if call.Data["API_KEY"] != "test-api-key" {
					t.Errorf("expected API_KEY=test-api-key, got %v", call.Data["API_KEY"])
				}
			},
		},
		{
			name: "missing path",
			opts: &ImportOptions{
				KVMount: "secret",
			},
			fileContent: `{}`,
			setupMock:   func(m *vault.MockClient) {},
			wantErr:     true,
			errMsg:      "path is required",
		},
		{
			name: "vault error",
			opts: &ImportOptions{
				KVMount: "secret",
				Path:    "myapp/config",
				Format:  "json",
			},
			fileContent: `{"API_KEY": "test-api-key"}`,
			setupMock: func(m *vault.MockClient) {
				m.KVPutErr = errors.New("permission denied")
			},
			wantErr: true,
			errMsg:  "failed to store secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := vault.NewMockClient()
			tt.setupMock(mockClient)

			app := NewWithClient(mockClient)

			// Create temp input file
			tmpDir := t.TempDir()
			var inputFile string
			if tt.opts.Format == "json" || tt.opts.Format == "" {
				inputFile = filepath.Join(tmpDir, "input.json")
			} else {
				inputFile = filepath.Join(tmpDir, "input.env")
			}
			if err := os.WriteFile(inputFile, []byte(tt.fileContent), 0600); err != nil {
				t.Fatalf("failed to write input file: %v", err)
			}
			tt.opts.Input = inputFile

			err := app.Import(tt.opts)

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

			if tt.checkStore != nil {
				tt.checkStore(t, mockClient)
			}
		})
	}
}

func TestAppImport_MissingInputFile(t *testing.T) {
	mockClient := vault.NewMockClient()
	app := NewWithClient(mockClient)

	err := app.Import(&ImportOptions{
		KVMount: "secret",
		Path:    "myapp/config",
		Input:   "/nonexistent/file.json",
	})

	if err == nil {
		t.Errorf("expected error for missing input file")
	}
	if !strings.Contains(err.Error(), "failed to read input file") {
		t.Errorf("error should mention failed to read input file: %v", err)
	}
}
