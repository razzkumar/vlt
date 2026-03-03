package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestAppCopy(t *testing.T) {
	tests := []struct {
		name      string
		opts      *CopyOptions
		setupMock func(*vault.MockClient)
		wantErr   bool
		errMsg    string
		wantGetN  int
		wantPutN  int
		verifyPut func(*testing.T, *vault.MockClient)
	}{
		{
			name: "copy single key secret",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "app/config-backup",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app/config", map[string]interface{}{
					"password": "s3cret",
				})
			},
			wantGetN: 2, // source read + dest existence check
			wantPutN: 1,
			verifyPut: func(t *testing.T, m *vault.MockClient) {
				if m.KVPutCalls[0].Data["password"] != "s3cret" {
					t.Errorf("expected password=s3cret, got %v", m.KVPutCalls[0].Data["password"])
				}
			},
		},
		{
			name: "copy multi-key secret",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "app/config-copy",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app/config", map[string]interface{}{
					"db_host":     "localhost",
					"db_port":     "5432",
					"db_password": "secret123",
				})
			},
			wantGetN: 2,
			wantPutN: 1,
			verifyPut: func(t *testing.T, m *vault.MockClient) {
				data := m.KVPutCalls[0].Data
				if len(data) != 3 {
					t.Errorf("expected 3 keys, got %d", len(data))
				}
				if data["db_host"] != "localhost" {
					t.Errorf("expected db_host=localhost, got %v", data["db_host"])
				}
			},
		},
		{
			name: "copy encrypted data raw (no decrypt)",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/encrypted",
				DestPath:   "app/encrypted-copy",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app/encrypted", map[string]interface{}{
					"api_key": "vault:v1:c2VjcmV0",
				})
			},
			wantGetN: 2,
			wantPutN: 1,
			verifyPut: func(t *testing.T, m *vault.MockClient) {
				if m.KVPutCalls[0].Data["api_key"] != "vault:v1:c2VjcmV0" {
					t.Errorf("encrypted data should be copied as-is, got %v", m.KVPutCalls[0].Data["api_key"])
				}
			},
		},
		{
			name: "default kv mount",
			opts: &CopyOptions{
				SourcePath: "app/config",
				DestPath:   "app/config-copy",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("home", "app/config", map[string]interface{}{
					"key": "value",
				})
			},
			wantGetN: 2,
			wantPutN: 1,
		},
		{
			name: "source not found",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/nonexistent",
				DestPath:   "app/backup",
			},
			setupMock: func(m *vault.MockClient) {},
			wantErr:   true,
			errMsg:    "failed to read source secret",
		},
		{
			name: "same source and dest",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "app/config",
			},
			setupMock: func(m *vault.MockClient) {},
			wantErr:   true,
			errMsg:    "source and destination paths must be different",
		},
		{
			name: "dest exists without force",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "app/existing",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app/config", map[string]interface{}{"key": "value"})
				m.SetSecret("secret", "app/existing", map[string]interface{}{"old": "data"})
			},
			wantErr: true,
			errMsg:  "destination already exists",
		},
		{
			name: "dest exists with force overwrites",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "app/existing",
				Force:      true,
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app/config", map[string]interface{}{"key": "new-value"})
				m.SetSecret("secret", "app/existing", map[string]interface{}{"old": "data"})
			},
			wantGetN: 1, // only source read, no dest check
			wantPutN: 1,
			verifyPut: func(t *testing.T, m *vault.MockClient) {
				if m.KVPutCalls[0].Data["key"] != "new-value" {
					t.Errorf("expected overwritten data, got %v", m.KVPutCalls[0].Data)
				}
			},
		},
		{
			name: "invalid source path",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "",
				DestPath:   "app/backup",
			},
			setupMock: func(m *vault.MockClient) {},
			wantErr:   true,
			errMsg:    "invalid source path",
		},
		{
			name: "invalid dest path",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "",
			},
			setupMock: func(m *vault.MockClient) {},
			wantErr:   true,
			errMsg:    "invalid destination path",
		},
		{
			name: "KVGet error propagated",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "app/backup",
			},
			setupMock: func(m *vault.MockClient) {
				m.KVGetErr = errors.New("permission denied")
			},
			wantErr: true,
			errMsg:  "failed to read source secret",
		},
		{
			name: "KVPut error propagated",
			opts: &CopyOptions{
				KVMount:    "secret",
				SourcePath: "app/config",
				DestPath:   "app/backup",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app/config", map[string]interface{}{"key": "value"})
				m.KVPutErr = errors.New("write denied")
			},
			wantErr: true,
			errMsg:  "failed to write destination secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := vault.NewMockClient()
			tt.setupMock(mockClient)

			app := NewWithClient(mockClient)
			err := app.Copy(tt.opts)

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

			if tt.wantGetN > 0 && len(mockClient.KVGetCalls) != tt.wantGetN {
				t.Errorf("expected %d KVGet calls, got %d", tt.wantGetN, len(mockClient.KVGetCalls))
			}

			if tt.wantPutN > 0 && len(mockClient.KVPutCalls) != tt.wantPutN {
				t.Errorf("expected %d KVPut calls, got %d", tt.wantPutN, len(mockClient.KVPutCalls))
			}

			if tt.verifyPut != nil {
				tt.verifyPut(t, mockClient)
			}
		})
	}
}

func TestAppCopyFromConfig(t *testing.T) {
	tests := []struct {
		name       string
		configYAML string
		setupMock  func(*vault.MockClient)
		opts       *CopyConfigOptions
		wantErr    bool
		errMsg     string
		wantPutN   int
	}{
		{
			name: "multiple copy pairs",
			configYAML: `copies:
  - from: app/config
    to: app/config-backup
  - from: db/creds
    to: db/creds-backup
`,
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("home", "app/config", map[string]interface{}{"key1": "val1"})
				m.SetSecret("home", "db/creds", map[string]interface{}{"user": "admin", "pass": "secret"})
			},
			opts:     &CopyConfigOptions{KVMount: "home"},
			wantPutN: 2,
		},
		{
			name: "config with custom kv mount",
			configYAML: `copies:
  - from: app/config
    to: app/backup
`,
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app/config", map[string]interface{}{"k": "v"})
			},
			opts:     &CopyConfigOptions{KVMount: "secret"},
			wantPutN: 1,
		},
		{
			name: "config with force overwrite",
			configYAML: `copies:
  - from: app/config
    to: app/existing
`,
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("home", "app/config", map[string]interface{}{"new": "data"})
				m.SetSecret("home", "app/existing", map[string]interface{}{"old": "data"})
			},
			opts:     &CopyConfigOptions{KVMount: "home", Force: true},
			wantPutN: 1,
		},
		{
			name: "config with force false and dest exists",
			configYAML: `copies:
  - from: app/config
    to: app/existing
`,
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("home", "app/config", map[string]interface{}{"new": "data"})
				m.SetSecret("home", "app/existing", map[string]interface{}{"old": "data"})
			},
			opts:    &CopyConfigOptions{KVMount: "home"},
			wantErr: true,
			errMsg:  "destination already exists",
		},
		{
			name:       "empty copies list",
			configYAML: "copies: []\n",
			setupMock:  func(m *vault.MockClient) {},
			opts:       &CopyConfigOptions{KVMount: "home"},
			wantErr:    true,
			errMsg:     "no copy entries found",
		},
		{
			name: "missing from field",
			configYAML: `copies:
  - to: app/backup
`,
			setupMock: func(m *vault.MockClient) {},
			opts:      &CopyConfigOptions{KVMount: "home"},
			wantErr:   true,
			errMsg:    "'from' is required",
		},
		{
			name: "missing to field",
			configYAML: `copies:
  - from: app/config
`,
			setupMock: func(m *vault.MockClient) {},
			opts:      &CopyConfigOptions{KVMount: "home"},
			wantErr:   true,
			errMsg:    "'to' is required",
		},
		{
			name:       "invalid yaml",
			configYAML: ": bad yaml [",
			setupMock:  func(m *vault.MockClient) {},
			opts:       &CopyConfigOptions{KVMount: "home"},
			wantErr:    true,
			errMsg:     "failed to parse config file",
		},
		{
			name: "partial failure stops on first error",
			configYAML: `copies:
  - from: app/config
    to: app/backup
  - from: app/missing
    to: app/missing-backup
`,
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("home", "app/config", map[string]interface{}{"k": "v"})
				// app/missing not set, will fail
			},
			opts:    &CopyConfigOptions{KVMount: "home"},
			wantErr: true,
			errMsg:  "copies[1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := vault.NewMockClient()
			tt.setupMock(mockClient)

			// Write config to temp file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "copy-config.yaml")
			if err := os.WriteFile(configPath, []byte(tt.configYAML), 0644); err != nil {
				t.Fatalf("failed to write temp config: %v", err)
			}

			a := NewWithClient(mockClient)
			err := a.CopyFromConfig(configPath, tt.opts)

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

			if tt.wantPutN > 0 && len(mockClient.KVPutCalls) != tt.wantPutN {
				t.Errorf("expected %d KVPut calls, got %d", tt.wantPutN, len(mockClient.KVPutCalls))
			}
		})
	}
}

func TestAppCopyFromConfig_FileNotFound(t *testing.T) {
	mockClient := vault.NewMockClient()
	a := NewWithClient(mockClient)

	err := a.CopyFromConfig("/nonexistent/config.yaml", &CopyConfigOptions{KVMount: "home"})
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	if !strings.Contains(err.Error(), "failed to read config file") {
		t.Errorf("error %q should mention config file read failure", err.Error())
	}
}
