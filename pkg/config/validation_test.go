package config

import (
	"testing"
)

func TestValidateEnvVarName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid cases
		{"simple uppercase", "FOO", false},
		{"simple lowercase", "foo", false},
		{"with underscore", "FOO_BAR", false},
		{"starts with underscore", "_FOO", false},
		{"mixed case", "Foo_Bar", false},
		{"with numbers", "FOO123", false},
		{"underscore and numbers", "FOO_123_BAR", false},

		// Invalid cases
		{"empty", "", true},
		{"starts with number", "123FOO", true},
		{"contains hyphen", "FOO-BAR", true},
		{"contains space", "FOO BAR", true},
		{"contains dot", "FOO.BAR", true},
		{"contains special char", "FOO@BAR", true},
		{"only numbers", "123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEnvVarName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEnvVarName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateVaultPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid cases
		{"simple path", "secrets", false},
		{"two segments", "secrets/app", false},
		{"three segments", "secrets/app/config", false},
		{"with hyphen", "secrets/my-app", false},
		{"with underscore", "secrets/my_app", false},
		{"with numbers", "secrets/app123", false},
		{"leading slash", "/secrets/app", false},
		{"trailing slash", "secrets/app/", false},

		// Invalid cases
		{"empty", "", true},
		{"only slashes", "///", true},
		{"double slashes", "secrets//app", true},
		{"contains space", "secrets/my app", true},
		{"contains special char", "secrets/app@prod", true},
		{"contains dot in segment", "secrets/app.config", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVaultPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateVaultPath(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecretKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid cases
		{"simple", "key", false},
		{"with underscore", "api_key", false},
		{"with hyphen", "api-key", false},
		{"with dot", "tls.crt", false},
		{"starts with underscore", "_key", false},
		{"mixed", "api_key-v2.cert", false},

		// Invalid cases
		{"empty", "", true},
		{"starts with number", "123key", true},
		{"starts with hyphen", "-key", true},
		{"starts with dot", ".key", true},
		{"contains space", "api key", true},
		{"contains special char", "api@key", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSecretKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateInjectFormat(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantEnvVar string
		wantPath   string
		wantErr    bool
	}{
		// Valid cases
		{"simple", "FOO=secrets/foo", "FOO", "secrets/foo", false},
		{"with spaces", " FOO = secrets/foo ", "FOO", "secrets/foo", false},
		{"complex path", "DB_PASSWORD=secrets/prod/db/password", "DB_PASSWORD", "secrets/prod/db/password", false},

		// Invalid cases
		{"no equals", "FOO", "", "", true},
		{"empty env var", "=secrets/foo", "", "", true},
		{"empty path", "FOO=", "", "", true},
		{"invalid env var", "123FOO=secrets/foo", "", "", true},
		{"invalid path", "FOO=secrets//foo", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envVar, path, err := ValidateInjectFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInjectFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if envVar != tt.wantEnvVar {
					t.Errorf("ValidateInjectFormat(%q) envVar = %q, want %q", tt.input, envVar, tt.wantEnvVar)
				}
				if path != tt.wantPath {
					t.Errorf("ValidateInjectFormat(%q) path = %q, want %q", tt.input, path, tt.wantPath)
				}
			}
		})
	}
}
