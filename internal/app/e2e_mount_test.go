//go:build integration

package app

import (
	"strings"
	"testing"
)

func TestE2E_MountExistsTrue(t *testing.T) {
	exists, err := testClient.MountExists(testKVMount)
	if err != nil {
		t.Fatalf("MountExists(%q): %v", testKVMount, err)
	}
	if !exists {
		t.Errorf("expected mount %q to exist", testKVMount)
	}
}

func TestE2E_MountExistsFalse(t *testing.T) {
	mount := "nonexistent-" + strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-"))
	exists, err := testClient.MountExists(mount)
	if err != nil {
		t.Fatalf("MountExists(%q): %v", mount, err)
	}
	if exists {
		t.Errorf("expected mount %q to not exist", mount)
	}
}

func TestE2E_CreateKVv2Mount(t *testing.T) {
	mount := "e2e-mt-" + strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-"))
	if len(mount) > 64 {
		mount = mount[:64]
	}

	if err := testClient.CreateKVv2Mount(mount); err != nil {
		t.Fatalf("CreateKVv2Mount(%q): %v", mount, err)
	}

	exists, err := testClient.MountExists(mount)
	if err != nil {
		t.Fatalf("MountExists(%q): %v", mount, err)
	}
	if !exists {
		t.Errorf("expected mount %q to exist after creation", mount)
	}
}

func TestE2E_CreateKVv2MountAndWrite(t *testing.T) {
	mount := "e2e-rw-" + strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-"))
	if len(mount) > 64 {
		mount = mount[:64]
	}
	path := testPath(t)

	t.Cleanup(func() {
		clearKVPath(t, mount, path)
	})

	if err := testClient.CreateKVv2Mount(mount); err != nil {
		t.Fatalf("CreateKVv2Mount(%q): %v", mount, err)
	}

	data := map[string]interface{}{"username": "admin", "password": "s3cr3t"}
	if err := testClient.KVPut(mount, path, data); err != nil {
		t.Fatalf("KVPut: %v", err)
	}

	got, err := testClient.KVGet(mount, path)
	if err != nil {
		t.Fatalf("KVGet: %v", err)
	}
	for k, v := range data {
		if got[k] != v {
			t.Errorf("key %s: want %v, got %v", k, v, got[k])
		}
	}
}
