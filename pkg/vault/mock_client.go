package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// MockClient is a mock implementation of VaultClient for testing
type MockClient struct {
	mu sync.RWMutex

	// In-memory KV storage: map[mount/path]data
	kvStore map[string]map[string]interface{}

	// Error injection
	KVGetErr          error
	KVPutErr          error
	KVDeleteErr       error
	KVListErr         error
	TransitEncryptErr error
	TransitDecryptErr error

	// Call tracking for assertions
	KVGetCalls          []KVGetCall
	KVPutCalls          []KVPutCall
	KVDeleteCalls       []KVDeleteCall
	KVListCalls         []KVListCall
	TransitEncryptCalls []TransitEncryptCall
	TransitDecryptCalls []TransitDecryptCall
}

// KVGetCall records a call to KVGet
type KVGetCall struct {
	Mount string
	Path  string
}

// KVDeleteCall records a call to KVDelete
type KVDeleteCall struct {
	Mount string
	Path  string
}

// KVListCall records a call to KVList
type KVListCall struct {
	Mount string
	Path  string
}

// KVPutCall records a call to KVPut
type KVPutCall struct {
	Mount string
	Path  string
	Data  map[string]interface{}
}

// TransitEncryptCall records a call to TransitEncrypt
type TransitEncryptCall struct {
	TransitMount string
	KeyName      string
	Plaintext    []byte
}

// TransitDecryptCall records a call to TransitDecrypt
type TransitDecryptCall struct {
	TransitMount string
	KeyName      string
	Ciphertext   string
}

// NewMockClient creates a new MockClient instance
func NewMockClient() *MockClient {
	return &MockClient{
		kvStore: make(map[string]map[string]interface{}),
	}
}

// Compile-time check that MockClient implements VaultClient
var _ VaultClient = (*MockClient)(nil)

// TransitEncrypt produces fake encrypted ciphertext: vault:v1:<base64-encoded-plaintext>
func (m *MockClient) TransitEncrypt(transitMount, keyName string, plaintext []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TransitEncryptCalls = append(m.TransitEncryptCalls, TransitEncryptCall{
		TransitMount: transitMount,
		KeyName:      keyName,
		Plaintext:    plaintext,
	})

	if m.TransitEncryptErr != nil {
		return "", m.TransitEncryptErr
	}

	if keyName == "" {
		return "", errors.New("transit key name required")
	}

	// Produce fake ciphertext that encodes the plaintext for easy verification
	encoded := base64.StdEncoding.EncodeToString(plaintext)
	return fmt.Sprintf("vault:v1:%s", encoded), nil
}

// TransitDecrypt decrypts fake ciphertext produced by TransitEncrypt
func (m *MockClient) TransitDecrypt(transitMount, keyName, ciphertext string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TransitDecryptCalls = append(m.TransitDecryptCalls, TransitDecryptCall{
		TransitMount: transitMount,
		KeyName:      keyName,
		Ciphertext:   ciphertext,
	})

	if m.TransitDecryptErr != nil {
		return nil, m.TransitDecryptErr
	}

	if keyName == "" {
		return nil, errors.New("transit key name required")
	}

	// Decode fake ciphertext: vault:v1:<base64-encoded-plaintext>
	if !strings.HasPrefix(ciphertext, "vault:v1:") {
		return nil, errors.New("invalid ciphertext format")
	}

	encoded := strings.TrimPrefix(ciphertext, "vault:v1:")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	return decoded, nil
}

// KVPut stores data in the mock KV store
func (m *MockClient) KVPut(mount, path string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.KVPutCalls = append(m.KVPutCalls, KVPutCall{
		Mount: mount,
		Path:  path,
		Data:  data,
	})

	if m.KVPutErr != nil {
		return m.KVPutErr
	}

	key := m.makeKey(mount, path)
	m.kvStore[key] = data

	return nil
}

// KVGet retrieves data from the mock KV store
func (m *MockClient) KVGet(mount, path string) (map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.KVGetCalls = append(m.KVGetCalls, KVGetCall{
		Mount: mount,
		Path:  path,
	})

	if m.KVGetErr != nil {
		return nil, m.KVGetErr
	}

	key := m.makeKey(mount, path)
	data, ok := m.kvStore[key]
	if !ok {
		return nil, errors.New("no data returned from vault")
	}

	return data, nil
}

// KVDelete deletes data from the mock KV store
func (m *MockClient) KVDelete(mount, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.KVDeleteCalls = append(m.KVDeleteCalls, KVDeleteCall{
		Mount: mount,
		Path:  path,
	})

	if m.KVDeleteErr != nil {
		return m.KVDeleteErr
	}

	key := m.makeKey(mount, path)
	delete(m.kvStore, key)

	return nil
}

// KVList lists keys in the mock KV store
func (m *MockClient) KVList(mount, path string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.KVListCalls = append(m.KVListCalls, KVListCall{
		Mount: mount,
		Path:  path,
	})

	if m.KVListErr != nil {
		return nil, m.KVListErr
	}

	prefix := m.makeKey(mount, path)
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	result := []string{}
	seen := make(map[string]bool)

	for key := range m.kvStore {
		if strings.HasPrefix(key, prefix) {
			// Extract the next path segment
			remainder := strings.TrimPrefix(key, prefix)
			parts := strings.SplitN(remainder, "/", 2)
			if len(parts) > 0 && parts[0] != "" {
				name := parts[0]
				if len(parts) > 1 {
					name += "/" // It's a directory
				}
				if !seen[name] {
					seen[name] = true
					result = append(result, name)
				}
			}
		}
	}

	return result, nil
}

// makeKey creates a storage key from mount and path
func (m *MockClient) makeKey(mount, path string) string {
	return fmt.Sprintf("%s/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))
}

// SetSecret is a helper method to pre-populate the mock KV store
func (m *MockClient) SetSecret(mount, path string, data map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(mount, path)
	m.kvStore[key] = data
}

// Reset clears all stored data and call history
func (m *MockClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.kvStore = make(map[string]map[string]interface{})
	m.KVGetCalls = nil
	m.KVPutCalls = nil
	m.KVDeleteCalls = nil
	m.KVListCalls = nil
	m.TransitEncryptCalls = nil
	m.TransitDecryptCalls = nil
	m.KVGetErr = nil
	m.KVPutErr = nil
	m.KVDeleteErr = nil
	m.KVListErr = nil
	m.TransitEncryptErr = nil
	m.TransitDecryptErr = nil
}
