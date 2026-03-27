//go:build integration

package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/testcontainers/testcontainers-go/modules/vault"

	"github.com/razzkumar/vlt/pkg/config"
	vaultpkg "github.com/razzkumar/vlt/pkg/vault"
)

const (
	testRootToken     = "root"
	testKVMount       = "home"
	testTransitMount  = "transit"
	testEncryptionKey = "app-secrets"
)

var (
	testVaultAddr string
	testApp       *App
	testClient    vaultpkg.VaultClient
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	container, err := vault.Run(ctx,
		"hashicorp/vault:latest",
		vault.WithToken(testRootToken),
		vault.WithInitCommand(
			"secrets enable -path=home kv-v2",
			"secrets enable transit",
			fmt.Sprintf("write -f transit/keys/%s", testEncryptionKey),
		),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start vault container: %v\n", err)
		os.Exit(1)
	}

	testVaultAddr, err = container.HttpHostAddress(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get vault address: %v\n", err)
		os.Exit(1)
	}

	cfg := &config.VaultConfig{
		Addr:       testVaultAddr,
		Token:      testRootToken,
		AuthMethod: "token",
		Timeout:    15,
	}
	realClient, err := vaultpkg.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create vault client: %v\n", err)
		os.Exit(1)
	}
	testClient = realClient
	testApp = NewWithClient(realClient)

	code := m.Run()

	_ = container.Terminate(ctx)
	os.Exit(code)
}

// testPath returns a unique Vault KV path derived from the test name.
func testPath(t *testing.T) string {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "-")
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ToLower(name)
	return "e2e/" + name
}

// clearKVPath deletes a secret at the given mount/path for cleanup.
func clearKVPath(t *testing.T, mount, path string) {
	t.Helper()
	_ = testClient.KVDelete(mount, path)
}
