//go:build integration

package app

import (
	"strings"
	"testing"
)

func TestE2E_CopySingleSecret(t *testing.T) {
	base := testPath(t)
	srcPath := base + "/src"
	dstPath := base + "/dst"

	t.Cleanup(func() {
		clearKVPath(t, testKVMount, srcPath)
		clearKVPath(t, testKVMount, dstPath)
	})

	data := map[string]interface{}{"key": "value", "secret": "s3cr3t"}
	if err := testClient.KVPut(testKVMount, srcPath, data); err != nil {
		t.Fatalf("setup KVPut: %v", err)
	}

	if err := testApp.Copy(&CopyOptions{
		KVMount:    testKVMount,
		SourcePath: srcPath,
		DestPath:   dstPath,
	}); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	got, err := testClient.KVGet(testKVMount, dstPath)
	if err != nil {
		t.Fatalf("KVGet dst: %v", err)
	}
	for k, v := range data {
		if got[k] != v {
			t.Errorf("key %s: want %v, got %v", k, v, got[k])
		}
	}
}

func TestE2E_CopyRecursive(t *testing.T) {
	base := testPath(t)
	srcBase := base + "/src"
	dstBase := base + "/dst"

	entries := []struct {
		key string
		val map[string]interface{}
	}{
		{"a", map[string]interface{}{"val": "alpha"}},
		{"b", map[string]interface{}{"val": "beta"}},
		{"c", map[string]interface{}{"val": "gamma"}},
	}

	t.Cleanup(func() {
		for _, e := range entries {
			clearKVPath(t, testKVMount, srcBase+"/"+e.key)
			clearKVPath(t, testKVMount, dstBase+"/"+e.key)
		}
	})

	for _, e := range entries {
		if err := testClient.KVPut(testKVMount, srcBase+"/"+e.key, e.val); err != nil {
			t.Fatalf("setup KVPut %s: %v", e.key, err)
		}
	}

	if err := testApp.Copy(&CopyOptions{
		KVMount:    testKVMount,
		SourcePath: srcBase,
		DestPath:   dstBase,
		Recursive:  true,
	}); err != nil {
		t.Fatalf("Copy recursive: %v", err)
	}

	for _, e := range entries {
		got, err := testClient.KVGet(testKVMount, dstBase+"/"+e.key)
		if err != nil {
			t.Fatalf("KVGet dst/%s: %v", e.key, err)
		}
		if got["val"] != e.val["val"] {
			t.Errorf("dst/%s val: want %v, got %v", e.key, e.val["val"], got["val"])
		}
	}
}

func TestE2E_CopyConflictNoForce(t *testing.T) {
	base := testPath(t)
	srcPath := base + "/src"
	dstPath := base + "/dst"

	t.Cleanup(func() {
		clearKVPath(t, testKVMount, srcPath)
		clearKVPath(t, testKVMount, dstPath)
	})

	if err := testClient.KVPut(testKVMount, srcPath, map[string]interface{}{"key": "source"}); err != nil {
		t.Fatalf("setup src: %v", err)
	}
	if err := testClient.KVPut(testKVMount, dstPath, map[string]interface{}{"key": "existing"}); err != nil {
		t.Fatalf("setup dst: %v", err)
	}

	err := testApp.Copy(&CopyOptions{
		KVMount:    testKVMount,
		SourcePath: srcPath,
		DestPath:   dstPath,
	})
	if err == nil {
		t.Fatal("expected error for conflict without force, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

func TestE2E_CopyForceOverwrite(t *testing.T) {
	base := testPath(t)
	srcPath := base + "/src"
	dstPath := base + "/dst"

	t.Cleanup(func() {
		clearKVPath(t, testKVMount, srcPath)
		clearKVPath(t, testKVMount, dstPath)
	})

	srcData := map[string]interface{}{"key": "new-value"}
	if err := testClient.KVPut(testKVMount, srcPath, srcData); err != nil {
		t.Fatalf("setup src: %v", err)
	}
	if err := testClient.KVPut(testKVMount, dstPath, map[string]interface{}{"key": "old-value"}); err != nil {
		t.Fatalf("setup dst: %v", err)
	}

	if err := testApp.Copy(&CopyOptions{
		KVMount:    testKVMount,
		SourcePath: srcPath,
		DestPath:   dstPath,
		Force:      true,
	}); err != nil {
		t.Fatalf("Copy with force: %v", err)
	}

	got, err := testClient.KVGet(testKVMount, dstPath)
	if err != nil {
		t.Fatalf("KVGet dst: %v", err)
	}
	if got["key"] != srcData["key"] {
		t.Errorf("dst key: want %v, got %v", srcData["key"], got["key"])
	}
}

func TestE2E_CopyCrossMountCreatesMount(t *testing.T) {
	srcPath := testPath(t)
	mountName := "e2e-bk-" + strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-"))
	if len(mountName) > 64 {
		mountName = mountName[:64]
	}

	t.Cleanup(func() {
		clearKVPath(t, testKVMount, srcPath)
		clearKVPath(t, mountName, srcPath)
	})

	srcData := map[string]interface{}{"token": "abc123"}
	if err := testClient.KVPut(testKVMount, srcPath, srcData); err != nil {
		t.Fatalf("setup src: %v", err)
	}

	if err := testApp.Copy(&CopyOptions{
		KVMount:     testKVMount,
		DestKVMount: mountName,
		SourcePath:  srcPath,
		DestPath:    srcPath,
	}); err != nil {
		t.Fatalf("Copy cross-mount: %v", err)
	}

	exists, err := testClient.MountExists(mountName)
	if err != nil {
		t.Fatalf("MountExists: %v", err)
	}
	if !exists {
		t.Error("expected new mount to exist after cross-mount copy")
	}

	got, err := testClient.KVGet(mountName, srcPath)
	if err != nil {
		t.Fatalf("KVGet from new mount: %v", err)
	}
	if got["token"] != srcData["token"] {
		t.Errorf("token: want %v, got %v", srcData["token"], got["token"])
	}
}
