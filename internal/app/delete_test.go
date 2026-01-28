package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestAppDelete(t *testing.T) {
	tests := []struct {
		name      string
		opts      *DeleteOptions
		setupMock func(*vault.MockClient)
		wantErr   bool
		errMsg    string
	}{
		{
			name: "delete existing secret",
			opts: &DeleteOptions{
				KVMount: "secret",
				Path:    "myapp/config",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "myapp/config", map[string]interface{}{
					"key": "value",
				})
			},
			wantErr: false,
		},
		{
			name: "delete with default mount",
			opts: &DeleteOptions{
				Path: "myapp/config",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("home", "myapp/config", map[string]interface{}{
					"key": "value",
				})
			},
			wantErr: false,
		},
		{
			name: "delete non-existent secret succeeds",
			opts: &DeleteOptions{
				KVMount: "secret",
				Path:    "nonexistent",
			},
			setupMock: func(m *vault.MockClient) {},
			wantErr:   false,
		},
		{
			name: "missing path",
			opts: &DeleteOptions{
				KVMount: "secret",
			},
			setupMock: func(m *vault.MockClient) {},
			wantErr:   true,
			errMsg:    "path is required",
		},
		{
			name: "vault error",
			opts: &DeleteOptions{
				KVMount: "secret",
				Path:    "myapp/config",
			},
			setupMock: func(m *vault.MockClient) {
				m.KVDeleteErr = errors.New("permission denied")
			},
			wantErr: true,
			errMsg:  "failed to delete secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := vault.NewMockClient()
			tt.setupMock(mockClient)

			app := NewWithClient(mockClient)
			err := app.Delete(tt.opts)

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

			// Verify delete was called
			if len(mockClient.KVDeleteCalls) != 1 {
				t.Errorf("expected 1 KVDelete call, got %d", len(mockClient.KVDeleteCalls))
			}
		})
	}
}

func TestAppDelete_VerifiesSecretRemoved(t *testing.T) {
	mockClient := vault.NewMockClient()
	mockClient.SetSecret("secret", "myapp/config", map[string]interface{}{
		"key": "value",
	})

	app := NewWithClient(mockClient)

	// Verify secret exists
	data, err := mockClient.KVGet("secret", "myapp/config")
	if err != nil {
		t.Fatalf("secret should exist before delete: %v", err)
	}
	if data["key"] != "value" {
		t.Fatalf("unexpected data: %v", data)
	}

	// Delete the secret
	err = app.Delete(&DeleteOptions{
		KVMount: "secret",
		Path:    "myapp/config",
	})
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Verify secret is gone
	_, err = mockClient.KVGet("secret", "myapp/config")
	if err == nil {
		t.Errorf("expected error after delete, secret should be gone")
	}
}
