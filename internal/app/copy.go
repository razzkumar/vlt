package app

import (
	"fmt"
	"os"

	"github.com/razzkumar/vlt/pkg/config"
	"gopkg.in/yaml.v3"
)

// CopyOptions contains options for the Copy operation
type CopyOptions struct {
	KVMount    string
	SourcePath string
	DestPath   string
	Force      bool
}

// CopyConfigOptions contains options for the CopyFromConfig operation
type CopyConfigOptions struct {
	KVMount string
	Force   bool
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
	kvMount := opts.KVMount
	if kvMount == "" {
		kvMount = "home"
	}

	if err := config.ValidateVaultPath(opts.SourcePath); err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}
	if err := config.ValidateVaultPath(opts.DestPath); err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	if opts.SourcePath == opts.DestPath {
		return fmt.Errorf("source and destination paths must be different")
	}

	// Read source
	data, err := a.vaultClient.KVGet(kvMount, opts.SourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source secret: %w", err)
	}

	// Check if destination exists (unless --force)
	if !opts.Force {
		_, err := a.vaultClient.KVGet(kvMount, opts.DestPath)
		if err == nil {
			return fmt.Errorf("destination already exists, use --force to overwrite")
		}
	}

	// Write to destination
	if err := a.vaultClient.KVPut(kvMount, opts.DestPath, data); err != nil {
		return fmt.Errorf("failed to write destination secret: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Copied %d key(s): %s/%s → %s/%s\n", len(data), kvMount, opts.SourcePath, kvMount, opts.DestPath)
	return nil
}

// CopyFromConfig reads a YAML config file with copy pairs and executes them
func (a *App) CopyFromConfig(configFile string, opts *CopyConfigOptions) error {
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

	kvMount := opts.KVMount
	if kvMount == "" {
		kvMount = "home"
	}

	for i, entry := range cfg.Copies {
		if entry.From == "" {
			return fmt.Errorf("copies[%d]: 'from' is required", i)
		}
		if entry.To == "" {
			return fmt.Errorf("copies[%d]: 'to' is required", i)
		}

		copyOpts := &CopyOptions{
			KVMount:    kvMount,
			SourcePath: entry.From,
			DestPath:   entry.To,
			Force:      opts.Force,
		}

		if err := a.Copy(copyOpts); err != nil {
			return fmt.Errorf("copies[%d] (%s → %s): %w", i, entry.From, entry.To, err)
		}
	}

	fmt.Fprintf(os.Stderr, "Completed %d copy operation(s)\n", len(cfg.Copies))
	return nil
}
