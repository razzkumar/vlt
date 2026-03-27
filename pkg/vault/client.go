package vault

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	// Auth methods implemented directly

	"github.com/razzkumar/vlt/pkg/config"
)

// Sentinel errors for common Vault operation failures
var (
	// ErrSecretNotFound is returned when a secret path has no data in Vault
	ErrSecretNotFound = errors.New("secret not found")
	// ErrUnexpectedFormat is returned when KV v2 response has unexpected structure
	ErrUnexpectedFormat = errors.New("unexpected kv v2 format")
)

// Client wraps the Vault API client with our specific functionality
type Client struct {
	client *vaultapi.Client
	config *config.VaultConfig
}

// NewClient creates a new Vault client
func NewClient(cfg *config.VaultConfig) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = cfg.Addr
	vaultConfig.Timeout = time.Duration(cfg.Timeout) * time.Second

	if cfg.CACert != "" || cfg.SkipVerify {
		if cfg.SkipVerify {
			fmt.Fprintf(os.Stderr, "WARNING: TLS verification is disabled. This is insecure and should only be used for testing.\n")
		}
		err := vaultConfig.ConfigureTLS(&vaultapi.TLSConfig{
			CACert:   cfg.CACert,
			Insecure: cfg.SkipVerify,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	client, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	// Authenticate and get token
	token, err := authenticateVault(client, cfg)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	client.SetToken(token)

	// Configure TLS properly
	if tr, ok := vaultConfig.HttpClient.Transport.(*http.Transport); ok && tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return &Client{
		client: client,
		config: cfg,
	}, nil
}

// TransitEncrypt encrypts plaintext using Vault's Transit secrets engine
func (c *Client) TransitEncrypt(transitMount, keyName string, plaintext []byte) (string, error) {
	if keyName == "" {
		return "", errors.New("transit key name required")
	}

	b64 := base64.StdEncoding.EncodeToString(plaintext)
	path := fmt.Sprintf("%s/encrypt/%s", strings.TrimSuffix(transitMount, "/"), keyName)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	secret, err := c.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"plaintext": b64,
	})
	if err != nil {
		return "", fmt.Errorf("transit encrypt failed: %w", err)
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok || ciphertext == "" {
		return "", errors.New("ciphertext missing in transit response")
	}

	return ciphertext, nil
}

// TransitDecrypt decrypts ciphertext using Vault's Transit secrets engine
func (c *Client) TransitDecrypt(transitMount, keyName, ciphertext string) ([]byte, error) {
	if keyName == "" {
		return nil, errors.New("transit key name required")
	}

	path := fmt.Sprintf("%s/decrypt/%s", strings.TrimSuffix(transitMount, "/"), keyName)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	secret, err := c.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("transit decrypt failed: %w", err)
	}

	b64, ok := secret.Data["plaintext"].(string)
	if !ok || b64 == "" {
		return nil, errors.New("plaintext missing in transit response")
	}

	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return dec, nil
}

// KVPut stores data in Vault's KV v2 secrets engine
func (c *Client) KVPut(mount, path string, data map[string]interface{}) error {
	apiPath := fmt.Sprintf("%s/data/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))
	payload := map[string]interface{}{"data": data}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	_, err := c.client.Logical().WriteWithContext(ctx, apiPath, payload)
	if err != nil {
		return fmt.Errorf("kv put failed: %w", err)
	}

	return nil
}

// KVGet retrieves data from Vault's KV v2 secrets engine
func (c *Client) KVGet(mount, path string) (map[string]interface{}, error) {
	apiPath := fmt.Sprintf("%s/data/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	secret, err := c.client.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		return nil, fmt.Errorf("kv get failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, ErrSecretNotFound
	}

	inner, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: missing 'data' field", ErrUnexpectedFormat)
	}

	return inner, nil
}

// KVDelete deletes a secret from Vault's KV v2 secrets engine
func (c *Client) KVDelete(mount, path string) error {
	apiPath := fmt.Sprintf("%s/data/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	_, err := c.client.Logical().DeleteWithContext(ctx, apiPath)
	if err != nil {
		return fmt.Errorf("kv delete failed: %w", err)
	}

	return nil
}

// KVList lists secrets at a path in Vault's KV v2 secrets engine
func (c *Client) KVList(mount, path string) ([]string, error) {
	apiPath := fmt.Sprintf("%s/metadata/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	secret, err := c.client.Logical().ListWithContext(ctx, apiPath)
	if err != nil {
		return nil, fmt.Errorf("kv list failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			result = append(result, s)
		}
	}

	return result, nil
}

// MountExists reports whether the named mount exists.
func (c *Client) MountExists(mount string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	mounts, err := c.client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("list mounts failed: %w", err)
	}

	normalized := strings.Trim(strings.TrimSpace(mount), "/")
	if normalized == "" {
		return false, errors.New("mount path required")
	}

	_, ok := mounts[normalized+"/"]
	return ok, nil
}

// CreateKVv2Mount creates a KV v2 mount at the provided path.
func (c *Client) CreateKVv2Mount(mount string) error {
	normalized := strings.Trim(strings.TrimSpace(mount), "/")
	if normalized == "" {
		return errors.New("mount path required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)
	defer cancel()

	err := c.client.Sys().MountWithContext(ctx, normalized, &vaultapi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		return fmt.Errorf("create kv v2 mount failed: %w", err)
	}

	return nil
}

// Addr returns the Vault server address this client is configured to use.
func (c *Client) Addr() string {
	return c.config.Addr
}

// authenticateVault performs authentication based on the configured method
func authenticateVault(client *vaultapi.Client, cfg *config.VaultConfig) (string, error) {
	switch cfg.AuthMethod {
	case "token":
		if cfg.Token == "" {
			return "", fmt.Errorf("token is required for token auth")
		}
		return cfg.Token, nil

	case "approle":
		return authenticateAppRole(client, cfg)

	case "github":
		return authenticateGitHub(client, cfg)

	case "kubernetes":
		return authenticateKubernetes(client, cfg)

	default:
		return "", fmt.Errorf("unsupported auth method: %s", cfg.AuthMethod)
	}
}

// authenticateAppRole performs AppRole authentication
func authenticateAppRole(client *vaultapi.Client, cfg *config.VaultConfig) (string, error) {
	data := map[string]interface{}{
		"role_id":   cfg.RoleID,
		"secret_id": cfg.SecretID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	secret, err := client.Logical().WriteWithContext(ctx, "auth/approle/login", data)
	if err != nil {
		return "", fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth info was returned after login")
	}

	return secret.Auth.ClientToken, nil
}

// authenticateGitHub performs GitHub personal access token authentication
func authenticateGitHub(client *vaultapi.Client, cfg *config.VaultConfig) (string, error) {
	data := map[string]interface{}{
		"token": cfg.GitHubToken,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	secret, err := client.Logical().WriteWithContext(ctx, "auth/github/login", data)
	if err != nil {
		return "", fmt.Errorf("unable to login to GitHub auth method: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth info was returned after login")
	}

	return secret.Auth.ClientToken, nil
}

// authenticateKubernetes performs Kubernetes service account authentication
func authenticateKubernetes(client *vaultapi.Client, cfg *config.VaultConfig) (string, error) {
	// Validate and clean the JWT path to prevent path traversal
	cleanPath := filepath.Clean(cfg.K8sJWTPath)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid K8s JWT path: path traversal detected in %s", cfg.K8sJWTPath)
	}
	allowedPrefixes := []string{"/var/run/secrets/", "/run/secrets/"}
	isStandard := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cleanPath, prefix) {
			isStandard = true
			break
		}
	}
	if !isStandard {
		fmt.Fprintf(os.Stderr, "Warning: K8s JWT path %q is outside standard service account directories\n", cleanPath)
	}

	// Read the service account token
	jwtBytes, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("unable to read Kubernetes JWT token from %s: %w", cfg.K8sJWTPath, err)
	}
	jwt := strings.TrimSpace(string(jwtBytes))

	data := map[string]interface{}{
		"role": cfg.K8sRole,
		"jwt":  jwt,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	path := fmt.Sprintf("auth/%s/login", cfg.K8sAuthPath)
	secret, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("unable to login to Kubernetes auth method: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("no auth info was returned after login")
	}

	return secret.Auth.ClientToken, nil
}
