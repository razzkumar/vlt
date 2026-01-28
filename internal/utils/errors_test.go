package utils

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorCollector_Add(t *testing.T) {
	ec := NewErrorCollector("")

	ec.Add(nil) // Should be ignored
	ec.Add(errors.New("error 1"))
	ec.Add(errors.New("error 2"))

	if ec.Count() != 2 {
		t.Errorf("expected 2 errors, got %d", ec.Count())
	}
}

func TestErrorCollector_HasErrors(t *testing.T) {
	ec := NewErrorCollector("")

	if ec.HasErrors() {
		t.Error("expected no errors initially")
	}

	ec.Add(errors.New("error"))

	if !ec.HasErrors() {
		t.Error("expected HasErrors to be true after adding error")
	}
}

func TestErrorCollector_Error_NoErrors(t *testing.T) {
	ec := NewErrorCollector("test")

	if ec.Error() != nil {
		t.Error("expected nil error when no errors collected")
	}
}

func TestErrorCollector_Error_SingleError(t *testing.T) {
	ec := NewErrorCollector("operation failed")
	ec.Add(errors.New("something went wrong"))

	err := ec.Error()
	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "operation failed") {
		t.Errorf("expected prefix in error: %v", err)
	}
	if !strings.Contains(err.Error(), "something went wrong") {
		t.Errorf("expected original error in message: %v", err)
	}
}

func TestErrorCollector_Error_MultipleErrors(t *testing.T) {
	ec := NewErrorCollector("batch operation")
	ec.Add(errors.New("error 1"))
	ec.Add(errors.New("error 2"))
	ec.Add(errors.New("error 3"))

	err := ec.Error()
	if err == nil {
		t.Fatal("expected error")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "3 errors") {
		t.Errorf("expected error count in message: %v", err)
	}
	if !strings.Contains(errStr, "error 1") {
		t.Errorf("expected error 1 in message: %v", err)
	}
	if !strings.Contains(errStr, "error 2") {
		t.Errorf("expected error 2 in message: %v", err)
	}
	if !strings.Contains(errStr, "error 3") {
		t.Errorf("expected error 3 in message: %v", err)
	}
}

func TestErrorCollector_AddWithContext(t *testing.T) {
	ec := NewErrorCollector("")
	ec.AddWithContext("secret/path", errors.New("not found"))

	err := ec.Error()
	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "secret/path") {
		t.Errorf("expected context in error: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected original error in message: %v", err)
	}
}

func TestIsTokenExpiredError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{nil, false},
		{errors.New("permission denied"), true},
		{errors.New("Error making API request: 403"), true},
		{errors.New("token expired"), true},
		{errors.New("missing client token"), true},
		{errors.New("invalid token"), true},
		{errors.New("something else"), false},
		{errors.New("no data returned from vault"), false},
	}

	for _, tt := range tests {
		t.Run(errorString(tt.err), func(t *testing.T) {
			result := IsTokenExpiredError(tt.err)
			if result != tt.expected {
				t.Errorf("IsTokenExpiredError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{nil, false},
		{errors.New("connection refused"), true},
		{errors.New("dial tcp: lookup vault.example.com: no such host"), true},
		{errors.New("timeout waiting for connection"), true},
		{errors.New("tls handshake failure"), true},
		{errors.New("x509: certificate signed by unknown authority"), true},
		{errors.New("permission denied"), false},
		{errors.New("no data returned from vault"), false},
	}

	for _, tt := range tests {
		t.Run(errorString(tt.err), func(t *testing.T) {
			result := IsConnectionError(tt.err)
			if result != tt.expected {
				t.Errorf("IsConnectionError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestWrapWithSuggestion(t *testing.T) {
	err := WrapWithSuggestion(errors.New("permission denied"), "Check your token")

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("expected original error: %v", err)
	}
	if !strings.Contains(err.Error(), "Suggestion:") {
		t.Errorf("expected suggestion label: %v", err)
	}
	if !strings.Contains(err.Error(), "Check your token") {
		t.Errorf("expected suggestion text: %v", err)
	}
}

func TestWrapWithSuggestion_Nil(t *testing.T) {
	err := WrapWithSuggestion(nil, "suggestion")
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestEnhanceError(t *testing.T) {
	t.Run("token expired error", func(t *testing.T) {
		err := EnhanceError(errors.New("permission denied"))
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "Suggestion") {
			t.Errorf("expected enhanced error with suggestion: %v", err)
		}
	})

	t.Run("connection error", func(t *testing.T) {
		err := EnhanceError(errors.New("connection refused"))
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "VAULT_ADDR") || !strings.Contains(err.Error(), "Suggestion") {
			t.Errorf("expected enhanced error with suggestion: %v", err)
		}
	})

	t.Run("regular error unchanged", func(t *testing.T) {
		originalErr := errors.New("some other error")
		err := EnhanceError(originalErr)
		if err != originalErr {
			t.Errorf("expected original error to be returned unchanged")
		}
	})

	t.Run("nil error", func(t *testing.T) {
		err := EnhanceError(nil)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
}

func errorString(err error) string {
	if err == nil {
		return "nil"
	}
	s := err.Error()
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
