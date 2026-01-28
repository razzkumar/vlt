package app

import (
	"testing"

	"github.com/razzkumar/vlt/pkg/vault"
)

func TestDecryptSingleValue(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	// Test decrypting a value (base64 of "my-secret")
	ciphertext := "vault:v1:bXktc2VjcmV0"
	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "my-key",
	}

	result, err := app.DecryptSingleValue(ciphertext, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "my-secret" {
		t.Errorf("expected 'my-secret', got %q", result)
	}
}

func TestDecryptSingleValue_MissingKey(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	ciphertext := "vault:v1:abc123"
	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "",
	}

	_, err := app.DecryptSingleValue(ciphertext, opts)
	if err == nil {
		t.Error("expected error for missing encryption key")
	}
}

func TestDecryptData_SingleEncrypted(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	data := map[string]interface{}{
		"ciphertext": "vault:v1:bXktc2VjcmV0", // base64 of "my-secret"
	}
	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "my-key",
	}

	result, err := app.DecryptData(data, "", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "my-secret" {
		t.Errorf("expected 'my-secret', got %v", result)
	}
}

func TestDecryptData_SinglePlaintext(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	data := map[string]interface{}{
		"value": "my-secret",
	}
	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "",
	}

	result, err := app.DecryptData(data, "", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "my-secret" {
		t.Errorf("expected 'my-secret', got %v", result)
	}
}

func TestDecryptData_MultiValuePlaintext(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	data := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}
	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "",
	}

	result, err := app.DecryptData(data, "", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}

	if resultMap["key1"] != "value1" {
		t.Errorf("expected key1='value1', got %v", resultMap["key1"])
	}
}

func TestDecryptData_SpecificKey(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	data := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}
	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "",
	}

	result, err := app.DecryptData(data, "key1", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "value1" {
		t.Errorf("expected 'value1', got %v", result)
	}
}

func TestDecryptData_KeyNotFound(t *testing.T) {
	mock := vault.NewMockClient()
	app := NewWithClient(mock)

	data := map[string]interface{}{
		"key1": "value1",
	}
	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "",
	}

	_, err := app.DecryptData(data, "nonexistent", opts)
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestGetSecretValue_SinglePlaintext(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/secret", map[string]interface{}{"value": "my-secret"})

	app := NewWithClient(mock)

	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "",
	}

	result, err := app.GetSecretValue(mock, "kv", "app/secret", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "my-secret" {
		t.Errorf("expected 'my-secret', got %q", result)
	}
}

func TestGetSecretValue_SingleEncrypted(t *testing.T) {
	mock := vault.NewMockClient()
	// base64 of "decrypted-value"
	mock.SetSecret("kv", "app/encrypted", map[string]interface{}{"ciphertext": "vault:v1:ZGVjcnlwdGVkLXZhbHVl"})

	app := NewWithClient(mock)

	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "my-key",
	}

	result, err := app.GetSecretValue(mock, "kv", "app/encrypted", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "decrypted-value" {
		t.Errorf("expected 'decrypted-value', got %q", result)
	}
}

func TestGetSecretValue_MultiValueError(t *testing.T) {
	mock := vault.NewMockClient()
	mock.SetSecret("kv", "app/multi", map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})

	app := NewWithClient(mock)

	opts := &DecryptOptions{
		TransitMount:  "transit",
		EncryptionKey: "",
	}

	_, err := app.GetSecretValue(mock, "kv", "app/multi", opts)
	if err == nil {
		t.Error("expected error for multi-value secret")
	}
}
