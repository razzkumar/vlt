package vault

import "testing"

func TestMockClientMountManagement(t *testing.T) {
	mock := NewMockClient()

	exists, err := mock.MountExists("home")
	if err != nil {
		t.Fatalf("unexpected error checking default mount: %v", err)
	}
	if !exists {
		t.Fatal("expected default home mount to exist")
	}

	exists, err = mock.MountExists("backup")
	if err != nil {
		t.Fatalf("unexpected error checking backup mount: %v", err)
	}
	if exists {
		t.Fatal("backup mount should not exist before creation")
	}

	if err := mock.CreateKVv2Mount("backup"); err != nil {
		t.Fatalf("unexpected error creating backup mount: %v", err)
	}

	exists, err = mock.MountExists("backup")
	if err != nil {
		t.Fatalf("unexpected error re-checking backup mount: %v", err)
	}
	if !exists {
		t.Fatal("backup mount should exist after creation")
	}

	info := mock.mounts["backup"]
	if info.Type != "kv" {
		t.Fatalf("expected kv mount type, got %q", info.Type)
	}
	if info.Options["version"] != "2" {
		t.Fatalf("expected kv v2 mount, got options %+v", info.Options)
	}
}
