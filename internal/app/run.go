package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/joho/godotenv"

	"github.com/razzkumar/vlt/pkg/config"
)

// RunOptions contains options for the Run operation
type RunOptions struct {
	KVMount       string
	TransitMount  string
	EncryptionKey string
	ConfigFile    string
	InjectSecrets []string // Format: "ENV_VAR=vault_path"
	EnvFile       string   // Additional .env file to load
	DryRun        bool     // Show env vars without running
	PreserveEnv   bool     // Preserve current environment
	Command       string   // Command to execute
	Args          []string // Arguments for the command
}

// Run executes a command with secrets injected as environment variables
func (a *App) Run(opts *RunOptions) error {
	effectiveEncryptionKey := config.GetEncryptionKey(opts.EncryptionKey)

	// Start with current environment if preserve-env is true
	envVars := make(map[string]string)
	if opts.PreserveEnv {
		for _, env := range os.Environ() {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				envVars[parts[0]] = parts[1]
			}
		}
	}

	// Load from .env file if specified
	if opts.EnvFile != "" {
		fileEnvVars, err := a.loadEnvFileForRun(opts.EnvFile)
		if err != nil {
			return fmt.Errorf("load env file %s: %w", opts.EnvFile, err)
		}
		for k, v := range fileEnvVars {
			envVars[k] = v
		}
	}

	// Load from config file if specified
	if opts.ConfigFile != "" {
		cfg, err := a.LoadConfig(opts.ConfigFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		configEnvVars, err := a.loadSecretsFromConfig(cfg, opts.KVMount, opts.TransitMount, effectiveEncryptionKey)
		if err != nil {
			return fmt.Errorf("load secrets from config: %w", err)
		}
		for k, v := range configEnvVars {
			envVars[k] = v
		}
	}

	// Load inline injected secrets
	if len(opts.InjectSecrets) > 0 {
		injectEnvVars, err := a.loadInlineSecrets(opts.InjectSecrets, opts.KVMount, opts.TransitMount, effectiveEncryptionKey)
		if err != nil {
			return fmt.Errorf("load inline secrets: %w", err)
		}
		for k, v := range injectEnvVars {
			envVars[k] = v
		}
	}

	// If dry-run, just print the environment variables
	if opts.DryRun {
		fmt.Println("Environment variables that would be set:")
		for k, v := range envVars {
			fmt.Printf("%s=%s\n", k, v)
		}
		fmt.Printf("\nCommand that would be executed: %s %s\n", opts.Command, strings.Join(opts.Args, " "))
		return nil
	}

	// Execute the command
	return a.executeCommand(opts.Command, opts.Args, envVars)
}

// loadEnvFileForRun loads environment variables from a .env file
func (a *App) loadEnvFileForRun(path string) (map[string]string, error) {
	// Use godotenv to parse the .env file
	envMap, err := godotenv.Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read .env file: %w", err)
	}
	return envMap, nil
}

// loadInlineSecrets loads secrets specified via --inject flags
func (a *App) loadInlineSecrets(injectSecrets []string, kvMount, transitMount, encryptionKey string) (map[string]string, error) {
	envVars := make(map[string]string)

	for _, inject := range injectSecrets {
		// Parse ENV_VAR=vault_path format
		parts := strings.SplitN(inject, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid inject format: %s (expected ENV_VAR=vault_path)", inject)
		}

		envVar := strings.TrimSpace(parts[0])
		vaultPath := strings.TrimSpace(parts[1])

		if envVar == "" || vaultPath == "" {
			return nil, fmt.Errorf("invalid inject format: %s (empty env var or vault path)", inject)
		}

		// Get secret from Vault
		data, err := a.vaultClient.KVGet(kvMount, vaultPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get secret %s: %w", vaultPath, err)
		}

		var secretValue string

		// Handle different secret types
		if ciphertext, ok := data["ciphertext"].(string); ok && strings.HasPrefix(ciphertext, "vault:v") {
			// Single encrypted value
			if encryptionKey == "" {
				return nil, fmt.Errorf("encryption key required for encrypted secret %s", vaultPath)
			}
			plaintext, err := a.vaultClient.TransitDecrypt(transitMount, encryptionKey, ciphertext)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt secret %s: %w", vaultPath, err)
			}
			secretValue = string(plaintext)
		} else if value, ok := data["value"].(string); ok {
			// Single plaintext value
			secretValue = value
		} else if len(data) == 1 {
			// Single value with any key
			for _, v := range data {
				secretValue = fmt.Sprintf("%v", v)
				break
			}
		} else {
			return nil, fmt.Errorf("secret %s contains multiple values, cannot inject as single environment variable", vaultPath)
		}

		envVars[envVar] = secretValue
	}

	return envVars, nil
}

// executeCommand runs the specified command with the provided environment variables
func (a *App) executeCommand(command string, args []string, envVars map[string]string) error {
	// Convert environment variables to []string format
	envSlice := make([]string, 0, len(envVars))
	for k, v := range envVars {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}

	// Create the command
	cmd := exec.Command(command, args...)
	cmd.Env = envSlice
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Run the command and wait for it to complete
	err := cmd.Run()
	if err != nil {
		// Check if it's an exit error to preserve the exit code
		if exitError, ok := err.(*exec.ExitError); ok {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}
