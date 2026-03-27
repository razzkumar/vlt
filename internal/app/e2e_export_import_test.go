//go:build integration

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_ExportJSON(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	if err := testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "API_KEY",
		Value:   "test-api-key",
	}); err != nil {
		t.Fatalf("Put API_KEY: %v", err)
	}
	if err := testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "DB_HOST",
		Value:   "localhost",
	}); err != nil {
		t.Fatalf("Put DB_HOST: %v", err)
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.json")

	if err := testApp.Export(&ExportOptions{
		KVMount: testKVMount,
		Path:    path,
		Format:  "json",
		Output:  outputFile,
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		t.Fatalf("Unmarshal JSON: %v", err)
	}

	if data["API_KEY"] != "test-api-key" {
		t.Errorf("expected API_KEY=test-api-key, got %v", data["API_KEY"])
	}
	if data["DB_HOST"] != "localhost" {
		t.Errorf("expected DB_HOST=localhost, got %v", data["DB_HOST"])
	}
}

func TestE2E_ExportEnv(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	if err := testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "SECRET_KEY",
		Value:   "my-secret",
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.env")

	if err := testApp.Export(&ExportOptions{
		KVMount: testKVMount,
		Path:    path,
		Format:  "env",
		Output:  outputFile,
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if !strings.Contains(string(content), `SECRET_KEY="my-secret"`) {
		t.Errorf("expected SECRET_KEY=\"my-secret\" in output, got: %s", content)
	}
}

func TestE2E_ImportJSON(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.json")
	if err := os.WriteFile(inputFile, []byte(`{"key1":"val1","key2":"val2"}`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := testApp.Import(&ImportOptions{
		KVMount: testKVMount,
		Path:    path,
		Format:  "json",
		Input:   inputFile,
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	data, err := testClient.KVGet(testKVMount, path)
	if err != nil {
		t.Fatalf("KVGet: %v", err)
	}

	if data["key1"] != "val1" {
		t.Errorf("expected key1=val1, got %v", data["key1"])
	}
	if data["key2"] != "val2" {
		t.Errorf("expected key2=val2, got %v", data["key2"])
	}
}

func TestE2E_ImportEnv(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.env")
	if err := os.WriteFile(inputFile, []byte("KEY1=val1\nKEY2=val2"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := testApp.Import(&ImportOptions{
		KVMount: testKVMount,
		Path:    path,
		Format:  "env",
		Input:   inputFile,
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	data, err := testClient.KVGet(testKVMount, path)
	if err != nil {
		t.Fatalf("KVGet: %v", err)
	}

	if data["KEY1"] != "val1" {
		t.Errorf("expected KEY1=val1, got %v", data["KEY1"])
	}
	if data["KEY2"] != "val2" {
		t.Errorf("expected KEY2=val2, got %v", data["KEY2"])
	}
}

func TestE2E_ExportImportRoundTrip(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	// Put 3 key-values
	for _, kv := range []struct{ k, v string }{
		{"ALPHA", "value-a"},
		{"BETA", "value-b"},
		{"GAMMA", "value-c"},
	} {
		if err := testApp.Put(&PutOptions{
			KVMount: testKVMount,
			KVPath:  path,
			Key:     kv.k,
			Value:   kv.v,
		}); err != nil {
			t.Fatalf("Put %s: %v", kv.k, err)
		}
	}

	tmpDir := t.TempDir()
	exportFile := filepath.Join(tmpDir, "export.json")

	// Export to JSON
	if err := testApp.Export(&ExportOptions{
		KVMount: testKVMount,
		Path:    path,
		Format:  "json",
		Output:  exportFile,
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Delete path
	if err := testApp.Delete(&DeleteOptions{
		KVMount: testKVMount,
		Path:    path,
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Import JSON back
	if err := testApp.Import(&ImportOptions{
		KVMount: testKVMount,
		Path:    path,
		Format:  "json",
		Input:   exportFile,
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Verify all keys match original
	data, err := testClient.KVGet(testKVMount, path)
	if err != nil {
		t.Fatalf("KVGet: %v", err)
	}

	expected := map[string]string{
		"ALPHA": "value-a",
		"BETA":  "value-b",
		"GAMMA": "value-c",
	}
	for k, v := range expected {
		if data[k] != v {
			t.Errorf("expected %s=%s, got %v", k, v, data[k])
		}
	}
}
