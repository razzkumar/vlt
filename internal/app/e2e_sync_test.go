//go:build integration

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_SyncGeneratesEnvFile(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	// Put secrets {DB_HOST: "localhost", DB_PORT: "5432"}
	for _, kv := range []struct{ k, v string }{
		{"DB_HOST", "localhost"},
		{"DB_PORT", "5432"},
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

	// Write .vlt.yaml config referencing the path
	configContent := fmt.Sprintf(`version: 1
kv:
  mount: %s
secrets:
  - path: %s
`, testKVMount, path)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".vlt.yaml")
	outputPath := filepath.Join(tmpDir, "output.env")

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}

	if err := testApp.GenerateEnvFile(configPath, outputPath, ""); err != nil {
		t.Fatalf("GenerateEnvFile: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	output := string(content)
	if !strings.Contains(output, "DB_HOST=localhost") {
		t.Errorf("expected DB_HOST=localhost in output, got: %s", output)
	}
	if !strings.Contains(output, "DB_PORT=5432") {
		t.Errorf("expected DB_PORT=5432 in output, got: %s", output)
	}
}

func TestE2E_SyncWithEncryption(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	// Store Transit-encrypted secrets
	for _, kv := range []struct{ k, v string }{
		{"SECRET_A", "plaintext-a"},
		{"SECRET_B", "plaintext-b"},
	} {
		if err := testApp.Put(&PutOptions{
			KVMount:       testKVMount,
			KVPath:        path,
			Key:           kv.k,
			Value:         kv.v,
			TransitMount:  testTransitMount,
			EncryptionKey: testEncryptionKey,
		}); err != nil {
			t.Fatalf("Put %s: %v", kv.k, err)
		}
	}

	// Write config with transit section
	configContent := fmt.Sprintf(`version: 1
kv:
  mount: %s
transit:
  mount: %s
  key: %s
secrets:
  - path: %s
`, testKVMount, testTransitMount, testEncryptionKey, path)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".vlt.yaml")
	outputPath := filepath.Join(tmpDir, "output.env")

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}

	if err := testApp.GenerateEnvFile(configPath, outputPath, testEncryptionKey); err != nil {
		t.Fatalf("GenerateEnvFile: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	output := string(content)
	if !strings.Contains(output, "SECRET_A=plaintext-a") {
		t.Errorf("expected SECRET_A=plaintext-a in decrypted output, got: %s", output)
	}
	if !strings.Contains(output, "SECRET_B=plaintext-b") {
		t.Errorf("expected SECRET_B=plaintext-b in decrypted output, got: %s", output)
	}
}
