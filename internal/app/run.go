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

// ExitError represents a command that exited with a non-zero status code.
// It is returned instead of calling os.Exit so callers can handle cleanup.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", e.Code)
}

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
	// Strict fails the command if any secret cannot be loaded
	Strict bool
	// Prefix adds a prefix to all injected environment variable names
	Prefix string
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
			if opts.Strict {
				return fmt.Errorf("load secrets from config: %w", err)
			}
			fmt.Fprintf(os.Stderr, "warning: some secrets could not be loaded: %v\n", err)
		}
		for k, v := range configEnvVars {
			key := k
			if opts.Prefix != "" {
				key = opts.Prefix + k
			}
			envVars[key] = v
		}
	}

	// Load inline injected secrets
	if len(opts.InjectSecrets) > 0 {
		injectEnvVars, err := a.loadInlineSecrets(opts.InjectSecrets, opts.KVMount, opts.TransitMount, effectiveEncryptionKey, opts.Strict)
		if err != nil {
			if opts.Strict {
				return fmt.Errorf("load inline secrets: %w", err)
			}
			fmt.Fprintf(os.Stderr, "warning: some inline secrets could not be loaded: %v\n", err)
		}
		for k, v := range injectEnvVars {
			key := k
			if opts.Prefix != "" {
				key = opts.Prefix + k
			}
			envVars[key] = v
		}
	}

	// If dry-run, just print the environment variable names (values are masked for security)
	if opts.DryRun {
		fmt.Println("Environment variables that would be set:")
		for k, v := range envVars {
			fmt.Printf("%s=%s\n", k, maskSecret(v))
		}
		fmt.Printf("\nCommand that would be executed: %s %s\n", opts.Command, strings.Join(opts.Args, " "))
		return nil
	}

	// Execute the command
	return a.executeCommand(opts.Command, opts.Args, envVars)
}

// maskSecret masks a secret value for safe display
func maskSecret(value string) string {
	if len(value) == 0 {
		return "(empty)"
	}
	return "****"
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
func (a *App) loadInlineSecrets(injectSecrets []string, kvMount, transitMount, encryptionKey string, strict bool) (map[string]string, error) {
	envVars := make(map[string]string)
	var lastErr error

	for _, inject := range injectSecrets {
		// Validate and parse ENV_VAR=vault_path format
		envVar, vaultPath, err := config.ValidateInjectFormat(inject)
		if err != nil {
			if strict {
				return nil, err
			}
			lastErr = err
			continue
		}

		// Get secret value using shared helper
		opts := &DecryptOptions{
			TransitMount:  transitMount,
			EncryptionKey: encryptionKey,
		}
		secretValue, err := a.GetSecretValue(a.vaultClient, kvMount, vaultPath, opts)
		if err != nil {
			if strict {
				return nil, fmt.Errorf("failed to get secret for %s: %w", envVar, err)
			}
			lastErr = err
			continue
		}

		envVars[envVar] = secretValue
	}

	return envVars, lastErr
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
				return &ExitError{Code: status.ExitStatus()}
			}
		}
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}
