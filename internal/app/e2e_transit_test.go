//go:build integration

package app

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_TransitEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("my-secret-data")

	ciphertext, err := testClient.TransitEncrypt(testTransitMount, testEncryptionKey, plaintext)
	if err != nil {
		t.Fatalf("TransitEncrypt failed: %v", err)
	}

	if !strings.HasPrefix(ciphertext, "vault:v1:") {
		t.Errorf("expected vault:v1: prefix, got %q", ciphertext)
	}

	decrypted, err := testClient.TransitDecrypt(testTransitMount, testEncryptionKey, ciphertext)
	if err != nil {
		t.Fatalf("TransitDecrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("expected decrypted %q, got %q", string(plaintext), string(decrypted))
	}
}

func TestE2E_PutWithTransitEncryption(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	err := testApp.Put(&PutOptions{
		KVMount:       testKVMount,
		KVPath:        path,
		TransitMount:  testTransitMount,
		EncryptionKey: testEncryptionKey,
		Key:           "secret",
		Value:         "mysecretvalue",
	})
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Raw KVGet to verify stored values are encrypted
	data, err := testClient.KVGet(testKVMount, path)
	if err != nil {
		t.Fatalf("KVGet failed: %v", err)
	}

	val, ok := data["secret"].(string)
	if !ok {
		t.Fatal("expected 'secret' key in stored data")
	}
	if !strings.HasPrefix(val, "vault:v1:") {
		t.Errorf("expected vault:v1: prefix, got %q", val)
	}
}

func TestE2E_GetWithTransitDecryption(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	// Put encrypted first
	err := testApp.Put(&PutOptions{
		KVMount:       testKVMount,
		KVPath:        path,
		TransitMount:  testTransitMount,
		EncryptionKey: testEncryptionKey,
		Key:           "secret",
		Value:         "mysecretvalue",
	})
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Capture stdout for Get output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = testApp.Get(&GetOptions{
		KVMount:       testKVMount,
		KVPath:        path,
		TransitMount:  testTransitMount,
		EncryptionKey: testEncryptionKey,
		Key:           "secret",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "mysecretvalue") {
		t.Errorf("expected output to contain 'mysecretvalue', got %q", output)
	}
}

func TestE2E_ExportDecryptsTransit(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	// Put encrypted secrets
	err := testApp.Put(&PutOptions{
		KVMount:       testKVMount,
		KVPath:        path,
		TransitMount:  testTransitMount,
		EncryptionKey: testEncryptionKey,
		Key:           "api_key",
		Value:         "plaintext-api-value",
	})
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Export with decryption to a temp file
	outputFile := filepath.Join(t.TempDir(), "exported.json")

	err = testApp.Export(&ExportOptions{
		KVMount:       testKVMount,
		Path:          path,
		TransitMount:  testTransitMount,
		EncryptionKey: testEncryptionKey,
		Format:        "json",
		Output:        outputFile,
	})
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if data["api_key"] != "plaintext-api-value" {
		t.Errorf("expected plaintext api_key='plaintext-api-value', got %v", data["api_key"])
	}
}
