package app

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestAppList(t *testing.T) {
	tests := []struct {
		name      string
		opts      *ListOptions
		setupMock func(*vault.MockClient)
		want      []string
		wantErr   bool
		errMsg    string
	}{
		{
			name: "list secrets at path",
			opts: &ListOptions{
				KVMount: "secret",
				Path:    "myapp",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "myapp/config", map[string]interface{}{"key": "value"})
				m.SetSecret("secret", "myapp/db", map[string]interface{}{"password": "secret"})
			},
			want:    []string{"config", "db"},
			wantErr: false,
		},
		{
			name: "list with default mount",
			opts: &ListOptions{
				Path: "myapp",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("home", "myapp/config", map[string]interface{}{"key": "value"})
			},
			want:    []string{"config"},
			wantErr: false,
		},
		{
			name: "list root path",
			opts: &ListOptions{
				KVMount: "secret",
			},
			setupMock: func(m *vault.MockClient) {
				m.SetSecret("secret", "app1/config", map[string]interface{}{"key": "value"})
				m.SetSecret("secret", "app2/config", map[string]interface{}{"key": "value"})
			},
			want:    []string{"app1/", "app2/"},
			wantErr: false,
		},
		{
			name: "list empty path",
			opts: &ListOptions{
				KVMount: "secret",
				Path:    "empty",
			},
			setupMock: func(m *vault.MockClient) {},
			want:      []string{},
			wantErr:   false,
		},
		{
			name: "vault error",
			opts: &ListOptions{
				KVMount: "secret",
				Path:    "myapp",
			},
			setupMock: func(m *vault.MockClient) {
				m.KVListErr = errors.New("permission denied")
			},
			wantErr: true,
			errMsg:  "failed to list secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := vault.NewMockClient()
			tt.setupMock(mockClient)

			app := NewWithClient(mockClient)
			got, err := app.List(tt.opts)

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

			// Sort both slices for comparison
			sort.Strings(got)
			sort.Strings(tt.want)

			if len(got) != len(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got %v, want %v", got, tt.want)
					return
				}
			}
		})
	}
}
