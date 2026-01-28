package vault

// VaultClient defines the interface for Vault operations
type VaultClient interface {
	// TransitEncrypt encrypts plaintext using Vault's Transit secrets engine
	TransitEncrypt(transitMount, keyName string, plaintext []byte) (string, error)

	// TransitDecrypt decrypts ciphertext using Vault's Transit secrets engine
	TransitDecrypt(transitMount, keyName, ciphertext string) ([]byte, error)

	// KVPut stores data in Vault's KV v2 secrets engine
	KVPut(mount, path string, data map[string]interface{}) error

	// KVGet retrieves data from Vault's KV v2 secrets engine
	KVGet(mount, path string) (map[string]interface{}, error)

	// KVDelete deletes a secret from Vault's KV v2 secrets engine
	KVDelete(mount, path string) error

	// KVList lists secrets at a path in Vault's KV v2 secrets engine
	KVList(mount, path string) ([]string, error)
}

// Compile-time check that Client implements VaultClient
var _ VaultClient = (*Client)(nil)
