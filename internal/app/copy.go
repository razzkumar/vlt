package app

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/razzkumar/vlt/pkg/config"
	"github.com/razzkumar/vlt/pkg/vault"
	"gopkg.in/yaml.v3"
)

// CopyOptions contains options for the Copy operation
type CopyOptions struct {
	KVMount     string
	DestKVMount string
	SourcePath  string
	DestPath    string
	Force       bool
	Recursive   bool
}

// CopyConfigOptions contains options for the CopyFromConfig operation
type CopyConfigOptions struct {
	KVMount     string
	DestKVMount string
	Force       bool
	Recursive   bool
}

// copyConfigFile represents the YAML config file for batch copies
type copyConfigFile struct {
	Copies []copyEntry `yaml:"copies"`
}

// copyEntry represents a single from/to copy pair in the config
type copyEntry struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// Copy copies all secret data from one Vault KV path to another
func (a *App) Copy(opts *CopyOptions) error {
	return a.copyWithClients(a.vaultClient, a.vaultClient, opts)
}

// CopyTo copies secret data from the app's Vault client to the provided destination client.
func (a *App) CopyTo(destClient vault.VaultClient, opts *CopyOptions) error {
	if destClient == nil {
		destClient = a.vaultClient
	}

	return a.copyWithClients(a.vaultClient, destClient, opts)
}

// CopyFromConfig reads a YAML config file with copy pairs and executes them
func (a *App) CopyFromConfig(configFile string, opts *CopyConfigOptions) error {
	return a.CopyFromConfigTo(a.vaultClient, configFile, opts)
}

// CopyFromConfigTo reads a YAML config file with copy pairs and executes them against the destination client.
func (a *App) CopyFromConfigTo(destClient vault.VaultClient, configFile string, opts *CopyConfigOptions) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg copyConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	if len(cfg.Copies) == 0 {
		return fmt.Errorf("no copy entries found in config file")
	}

	kvMount := "home"
	destKVMount := ""
	force := false
	recursive := false
	if opts != nil {
		if opts.KVMount != "" {
			kvMount = opts.KVMount
		}
		destKVMount = opts.DestKVMount
		force = opts.Force
		recursive = opts.Recursive
	}

	// Ensure destination mount exists once before processing entries
	destMountResolved := destKVMount
	if destMountResolved == "" {
		destMountResolved = kvMount
	}
	if err := ensureDestinationMount(destClient, destMountResolved); err != nil {
		return fmt.Errorf("failed to ensure destination mount: %w", err)
	}

	for i, entry := range cfg.Copies {
		if entry.From == "" {
			return fmt.Errorf("copies[%d]: 'from' is required", i)
		}
		if entry.To == "" {
			return fmt.Errorf("copies[%d]: 'to' is required", i)
		}

		copyOpts := &CopyOptions{
			KVMount:     kvMount,
			DestKVMount: destKVMount,
			SourcePath:  entry.From,
			DestPath:    entry.To,
			Force:       force,
			Recursive:   recursive,
		}

		if err := a.CopyTo(destClient, copyOpts); err != nil {
			return fmt.Errorf("copies[%d] (%s → %s): %w", i, entry.From, entry.To, err)
		}
	}

	fmt.Fprintf(os.Stderr, "Completed %d copy operation(s)\n", len(cfg.Copies))
	return nil
}

type copyResult struct {
	secrets int
	keys    int
}

func (a *App) copyWithClients(sourceClient, destClient vault.VaultClient, opts *CopyOptions) error {
	sourceMount := opts.KVMount
	if sourceMount == "" {
		sourceMount = "home"
	}
	destMount := opts.DestKVMount
	if destMount == "" {
		destMount = sourceMount
	}

	if err := config.ValidateVaultPath(opts.SourcePath); err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}
	if err := config.ValidateVaultPath(opts.DestPath); err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	if sourceClient.Addr() == destClient.Addr() && sourceMount == destMount && opts.SourcePath == opts.DestPath {
		return fmt.Errorf("source and destination paths must be different")
	}

	if err := ensureDestinationMount(destClient, destMount); err != nil {
		return fmt.Errorf("failed to ensure destination mount: %w", err)
	}

	var (
		result copyResult
		err    error
	)
	if opts.Recursive {
		result, err = copyRecursiveSecrets(sourceClient, destClient, sourceMount, destMount, opts.SourcePath, opts.DestPath, opts.Force)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Copied %d secret(s), %d key(s): %s/%s → %s/%s\n", result.secrets, result.keys, sourceMount, opts.SourcePath, destMount, opts.DestPath)
		return nil
	}

	result, err = copySingleSecret(sourceClient, destClient, sourceMount, destMount, opts.SourcePath, opts.DestPath, opts.Force)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Copied %d key(s): %s/%s → %s/%s\n", result.keys, sourceMount, opts.SourcePath, destMount, opts.DestPath)
	return nil
}

func ensureDestinationMount(client vault.VaultClient, mount string) error {
	exists, err := client.MountExists(mount)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	return client.CreateKVv2Mount(mount)
}

func copySingleSecret(sourceClient, destClient vault.VaultClient, sourceMount, destMount, sourcePath, destPath string, force bool) (copyResult, error) {
	data, err := sourceClient.KVGet(sourceMount, sourcePath)
	if err != nil {
		return copyResult{}, fmt.Errorf("failed to read source secret: %w", err)
	}

	if !force {
		_, err := destClient.KVGet(destMount, destPath)
		if err == nil {
			return copyResult{}, fmt.Errorf("destination already exists, use --force to overwrite")
		}
		if !errors.Is(err, vault.ErrSecretNotFound) {
			return copyResult{}, fmt.Errorf("failed to check destination secret: %w", err)
		}
	}

	if err := destClient.KVPut(destMount, destPath, data); err != nil {
		return copyResult{}, fmt.Errorf("failed to write destination secret: %w", err)
	}

	return copyResult{secrets: 1, keys: len(data)}, nil
}

func copyRecursiveSecrets(sourceClient, destClient vault.VaultClient, sourceMount, destMount, sourceRoot, destRoot string, force bool) (copyResult, error) {
	sourcePaths, err := collectSourcePaths(sourceClient, sourceMount, sourceRoot)
	if err != nil {
		return copyResult{}, err
	}

	var result copyResult
	for _, sourcePath := range sourcePaths {
		destPath := mapDestinationPath(sourceRoot, destRoot, sourcePath)
		singleResult, err := copySingleSecret(sourceClient, destClient, sourceMount, destMount, sourcePath, destPath, force)
		if err != nil {
			return copyResult{}, fmt.Errorf("%s/%s → %s/%s: %w", sourceMount, sourcePath, destMount, destPath, err)
		}

		result.secrets += singleResult.secrets
		result.keys += singleResult.keys
	}

	return result, nil
}

func collectSourcePaths(client vault.VaultClient, mount, root string) ([]string, error) {
	var paths []string
	seen := make(map[string]struct{})

	_, err := client.KVGet(mount, root)
	switch {
	case err == nil:
		paths = append(paths, root)
		seen[root] = struct{}{}
	case errors.Is(err, vault.ErrSecretNotFound):
	default:
		return nil, fmt.Errorf("failed to read source secret: %w", err)
	}

	if err := walkSourceTree(client, mount, root, seen, &paths); err != nil {
		return nil, err
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("source path not found: %s/%s", mount, root)
	}

	return paths, nil
}

func walkSourceTree(client vault.VaultClient, mount, path string, seen map[string]struct{}, paths *[]string) error {
	entries, err := client.KVList(mount, path)
	if err != nil {
		return fmt.Errorf("failed to list source path %s/%s: %w", mount, path, err)
	}

	for _, entry := range entries {
		cleanEntry := strings.TrimSuffix(entry, "/")
		childPath := joinVaultPath(path, cleanEntry)
		if strings.HasSuffix(entry, "/") {
			if err := walkSourceTree(client, mount, childPath, seen, paths); err != nil {
				return err
			}
			continue
		}

		if _, ok := seen[childPath]; ok {
			continue
		}
		seen[childPath] = struct{}{}
		*paths = append(*paths, childPath)
	}

	return nil
}

func mapDestinationPath(sourceRoot, destRoot, sourcePath string) string {
	if sourcePath == sourceRoot {
		return destRoot
	}

	relativePath := strings.TrimPrefix(sourcePath, sourceRoot)
	relativePath = strings.TrimPrefix(relativePath, "/")
	return joinVaultPath(destRoot, relativePath)
}

func joinVaultPath(base, child string) string {
	base = strings.Trim(base, "/")
	child = strings.Trim(child, "/")

	switch {
	case base == "":
		return child
	case child == "":
		return base
	default:
		return base + "/" + child
	}
}
