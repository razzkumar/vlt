//go:build integration

package app

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestE2E_PutGetSingleValue(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	err := testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "mykey",
		Value:   "myvalue",
	})
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = testApp.Get(&GetOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "mykey",
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "myvalue") {
		t.Errorf("expected output to contain 'myvalue', got %q", buf.String())
	}
}

func TestE2E_PutGetMultipleKeys(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	kvPairs := []struct{ k, v string }{
		{"db_host", "localhost"},
		{"db_port", "5432"},
		{"db_name", "mydb"},
	}
	for _, kv := range kvPairs {
		err := testApp.Put(&PutOptions{
			KVMount: testKVMount,
			KVPath:  path,
			Key:     kv.k,
			Value:   kv.v,
		})
		if err != nil {
			t.Fatalf("Put %s failed: %v", kv.k, err)
		}
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := testApp.Get(&GetOptions{
		KVMount: testKVMount,
		KVPath:  path,
	})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	for _, kv := range kvPairs {
		if !strings.Contains(output, kv.v) {
			t.Errorf("expected output to contain %q (key %q), got %q", kv.v, kv.k, output)
		}
	}
}

func TestE2E_PutMerge(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	err := testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "key1",
		Value:   "val1",
	})
	if err != nil {
		t.Fatalf("first Put failed: %v", err)
	}

	err = testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "key2",
		Value:   "val2",
	})
	if err != nil {
		t.Fatalf("second Put failed: %v", err)
	}

	data, err := testClient.KVGet(testKVMount, path)
	if err != nil {
		t.Fatalf("KVGet failed: %v", err)
	}

	if data["key1"] != "val1" {
		t.Errorf("expected key1=val1, got %v", data["key1"])
	}
	if data["key2"] != "val2" {
		t.Errorf("expected key2=val2, got %v", data["key2"])
	}
}

func TestE2E_PutForceOverwrite(t *testing.T) {
	path := testPath(t)
	t.Cleanup(func() { clearKVPath(t, testKVMount, path) })

	for _, kv := range []struct{ k, v string }{{"key_a", "alpha"}, {"key_b", "beta"}} {
		err := testApp.Put(&PutOptions{
			KVMount: testKVMount,
			KVPath:  path,
			Key:     kv.k,
			Value:   kv.v,
		})
		if err != nil {
			t.Fatalf("Put %s failed: %v", kv.k, err)
		}
	}

	err := testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "key_c",
		Value:   "gamma",
		Force:   true,
	})
	if err != nil {
		t.Fatalf("Force Put failed: %v", err)
	}

	data, err := testClient.KVGet(testKVMount, path)
	if err != nil {
		t.Fatalf("KVGet failed: %v", err)
	}

	if _, ok := data["key_a"]; ok {
		t.Error("expected key_a to be absent after force overwrite")
	}
	if _, ok := data["key_b"]; ok {
		t.Error("expected key_b to be absent after force overwrite")
	}
	if data["key_c"] != "gamma" {
		t.Errorf("expected key_c=gamma, got %v", data["key_c"])
	}
}

func TestE2E_GetNonExistent(t *testing.T) {
	err := testApp.Get(&GetOptions{
		KVMount: testKVMount,
		KVPath:  "e2e/nonexistent-path-that-does-not-exist",
	})
	if err == nil {
		t.Error("expected error for non-existent path, got nil")
	}
}

func TestE2E_Delete(t *testing.T) {
	path := testPath(t)

	err := testApp.Put(&PutOptions{
		KVMount: testKVMount,
		KVPath:  path,
		Key:     "key",
		Value:   "value",
	})
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = testApp.Delete(&DeleteOptions{
		KVMount: testKVMount,
		Path:    path,
	})
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	err = testApp.Get(&GetOptions{
		KVMount: testKVMount,
		KVPath:  path,
	})
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestE2E_List(t *testing.T) {
	base := testPath(t)
	subPaths := []string{base + "/a", base + "/b", base + "/c"}
	for _, p := range subPaths {
		t.Cleanup(func() { clearKVPath(t, testKVMount, p) })
	}

	for _, p := range subPaths {
		err := testApp.Put(&PutOptions{
			KVMount: testKVMount,
			KVPath:  p,
			Key:     "key",
			Value:   "value",
		})
		if err != nil {
			t.Fatalf("Put %s failed: %v", p, err)
		}
	}

	keys, err := testApp.List(&ListOptions{
		KVMount: testKVMount,
		Path:    base,
	})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d: %v", len(keys), keys)
	}
	for _, expected := range []string{"a", "b", "c"} {
		found := false
		for _, k := range keys {
			if k == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in list result, got %v", expected, keys)
		}
	}
}

func TestE2E_ListEmpty(t *testing.T) {
	keys, err := testApp.List(&ListOptions{
		KVMount: testKVMount,
		Path:    "e2e/nonexistent-prefix-that-does-not-exist",
	})
	// Vault KV v2 may return an error or empty list for a non-existent prefix
	if err != nil {
		return
	}
	if len(keys) != 0 {
		t.Errorf("expected empty list for non-existent prefix, got %v", keys)
	}
}
