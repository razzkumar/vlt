package cli

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/razzkumar/vlt/internal/app"
	"github.com/razzkumar/vlt/internal/utils"
	"github.com/razzkumar/vlt/pkg/config"
)

// GetCommands returns all CLI commands
func GetCommands() []*cli.Command {
	return []*cli.Command{
		getPutCommand(),
		getGetCommand(),
		getDeleteCommand(),
		getListCommand(),
		getCopyCommand(),
		getExportCommand(),
		getImportCommand(),
		getSyncCommand(),
		getRunCommand(),
		getJSONCommand(),
		getCompletionCommand(),
	}
}

func getPutCommand() *cli.Command {
	return &cli.Command{
		Name:    "put",
		Usage:   "Store/update secrets in Vault (merges with existing data)",
		Aliases: []string{"p"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "path",
				Usage:    "KV path to store secret(s)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "encryption-key",
				Usage: "Transit encryption key name (optional)",
			},
			&cli.StringFlag{
				Name:  "key",
				Usage: "Specific key to update in multi-value secret",
			},
			&cli.StringFlag{
				Name:  "value",
				Usage: "Secret value (or use stdin)",
			},
			&cli.StringFlag{
				Name:  "env-file",
				Usage: "Load multiple key-value pairs from .env file (default: .env)",
				Value: ".env",
			},
			&cli.StringFlag{
				Name:  "from-file",
				Usage: "Load file content as base64 encoded value with type=file metadata",
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
			&cli.StringFlag{
				Name:  "transit-mount",
				Usage: "Transit mount path",
				Value: "transit",
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "Overwrite existing data instead of merging",
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "Show what would be done without making changes",
			},
		},
		Action: func(ctx *cli.Context) error {
			// Validate input options - check if explicit inputs are provided
			inputCount := 0
			if ctx.String("value") != "" {
				inputCount++
			}
			// Only count env-file as input if explicitly provided (not default)
			if ctx.IsSet("env-file") {
				inputCount++
			}
			if ctx.String("from-file") != "" {
				inputCount++
			}

			if inputCount > 1 {
				return fmt.Errorf("only one of --value, --env-file, or --from-file can be specified")
			}

			// Validate key update operation
			if ctx.String("key") != "" && (ctx.IsSet("env-file") || ctx.String("from-file") != "") {
				return fmt.Errorf("--key cannot be used with --env-file or --from-file")
			}

			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			// Determine env file to use
			envFile := ""
			// If no explicit input provided, use default .env file if it exists
			if inputCount == 0 {
				if _, err := os.Stat(".env"); err == nil {
					envFile = ".env"
				} else {
					return fmt.Errorf("no input provided: specify --value, --env-file, --from-file, or create a .env file in the current directory")
				}
			} else if ctx.IsSet("env-file") {
				envFile = ctx.String("env-file")
			}

			opts := &app.PutOptions{
				KVMount:       ctx.String("kv-mount"),
				KVPath:        ctx.String("path"),
				TransitMount:  ctx.String("transit-mount"),
				EncryptionKey: ctx.String("encryption-key"),
				Key:           ctx.String("key"),
				Value:         ctx.String("value"),
				FromEnv:       envFile,
				FromFile:      ctx.String("from-file"),
				Force:         ctx.Bool("force"),
				DryRun:        ctx.Bool("dry-run"),
			}

			return appInstance.Put(opts)
		},
	}
}

func getGetCommand() *cli.Command {
	return &cli.Command{
		Name:    "get",
		Usage:   "Retrieve and optionally decrypt secrets from Vault",
		Aliases: []string{"g"},
		Description: `Retrieve secrets from Vault either by direct path or from a config file.

Examples:
  # Get secrets from specific path
  vlt get --path secrets/prod
  
  # Get all secrets from config file
  vlt get --config secrets.yaml
  
  # Get secrets from default config file (.vlt.yaml)
  vlt get
  
	  # Get specific key from multi-value secret
	  vlt get --path secrets/config --key database_password
  
  # Output as JSON
  vlt get --config secrets.yaml --json`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "path",
				Usage: "KV path to retrieve secret",
			},
			&cli.StringFlag{
				Name:  "config",
				Usage: "YAML config file (search order: VLT_CONFIG env var, ./.vlt.yaml, ~/.vlt.yaml)",
			},
			&cli.StringFlag{
				Name:  "encryption-key",
				Usage: "Transit encryption key name (required for encrypted secrets)",
			},
			&cli.StringFlag{
				Name:  "key",
				Usage: "Specific key to retrieve (for multi-value secrets)",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output as JSON format",
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
			&cli.StringFlag{
				Name:  "transit-mount",
				Usage: "Transit mount path",
				Value: "transit",
			},
			&cli.BoolFlag{
				Name:  "raw",
				Usage: "Output raw value without newline",
			},
			&cli.StringFlag{
				Name:  "default",
				Usage: "Default value if secret not found",
			},
		},
		Action: func(ctx *cli.Context) error {
			// Check for default config file if neither path nor config specified
			configFile := ctx.String("config")
			kvPath := ctx.String("path")

			if configFile == "" && kvPath == "" {
				// Check for default config file (current directory, then global)
				configFile = findConfigFile()
			}

			// Validate that we have either path or config
			if kvPath == "" && configFile == "" {
				return fmt.Errorf("either --path, --config, or config file (VLT_CONFIG env, ./.vlt.yaml, ~/.vlt.yaml) must be specified")
			}

			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			if configFile != "" {
				// Use config file to get all secrets
				return appInstance.GetFromConfigWithOptions(configFile, &app.GetFromConfigOptions{
					EncryptionKey: ctx.String("encryption-key"),
					OutputJSON:    ctx.Bool("json"),
				})
			} else {
				// Load config for file storage settings if available
				var cfg *config.Config
				if configFile := findConfigFile(); configFile != "" {
					if loadedCfg, err := appInstance.LoadConfig(configFile); err == nil {
						cfg = loadedCfg
					}
				}

				// Use direct path
				opts := &app.GetOptions{
					KVMount:       ctx.String("kv-mount"),
					KVPath:        kvPath,
					TransitMount:  ctx.String("transit-mount"),
					EncryptionKey: ctx.String("encryption-key"),
					Key:           ctx.String("key"),
					OutputJSON:    ctx.Bool("json"),
					Raw:           ctx.Bool("raw"),
					Default:       ctx.String("default"),
					Config:        cfg,
				}
				return appInstance.Get(opts)
			}
		},
	}
}

func getDeleteCommand() *cli.Command {
	return &cli.Command{
		Name:    "delete",
		Usage:   "Delete a secret from Vault",
		Aliases: []string{"d", "rm"},
		Description: `Delete a secret from Vault's KV v2 secrets engine.

Examples:
  # Delete a secret
  vlt delete --path secrets/myapp/config

  # Delete with custom KV mount
  vlt delete --path myapp/config --kv-mount secret`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "path",
				Usage:    "KV path of secret to delete",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
		},
		Action: func(ctx *cli.Context) error {
			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			opts := &app.DeleteOptions{
				KVMount: ctx.String("kv-mount"),
				Path:    ctx.String("path"),
			}

			if err := appInstance.Delete(opts); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Secret deleted: %s\n", opts.Path)
			return nil
		},
	}
}

func getCopyCommand() *cli.Command {
	return &cli.Command{
		Name:    "copy",
		Usage:   "Copy secrets from one path to another",
		Aliases: []string{"c", "cp"},
		Description: `Copy secrets from one Vault KV path to another. Data is copied as-is (raw copy).

Supports both single-path and config-file modes:

Single path mode:
  vlt copy --from secrets/app/config --to secrets/app/config-backup

Config file mode (YAML with source/dest pairs):
  vlt copy --config copy-config.yaml

Config file format:
  copies:
    - from: secrets/app/config
      to: secrets/app/config-backup
    - from: secrets/db/creds
      to: secrets/db/creds-backup

Examples:
  # Copy a secret to a new path
  vlt copy --from secrets/myapp/config --to secrets/myapp/config-backup

  # Copy with custom KV mount
  vlt copy --from myapp/config --to myapp/backup --kv-mount secret

  # Overwrite existing destination
  vlt copy --from myapp/config --to myapp/backup --force

  # Copy multiple paths from config file
  vlt copy --config copy-config.yaml --force`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "from",
				Usage: "Source KV path to copy from",
			},
			&cli.StringFlag{
				Name:  "to",
				Usage: "Destination KV path to copy to",
			},
			&cli.StringFlag{
				Name:  "config",
				Usage: "YAML config file with copy pairs (copies: [{from, to}])",
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "Overwrite if destination already exists",
			},
		},
		Action: func(ctx *cli.Context) error {
			configFile := ctx.String("config")
			from := ctx.String("from")
			to := ctx.String("to")

			if configFile == "" && from == "" && to == "" {
				return fmt.Errorf("either --from/--to or --config must be specified")
			}

			if configFile != "" && (from != "" || to != "") {
				return fmt.Errorf("cannot use --from/--to with --config")
			}

			if configFile == "" {
				if from == "" {
					return fmt.Errorf("--from is required")
				}
				if to == "" {
					return fmt.Errorf("--to is required")
				}
			}

			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			if configFile != "" {
				return appInstance.CopyFromConfig(configFile, &app.CopyConfigOptions{
					KVMount: ctx.String("kv-mount"),
					Force:   ctx.Bool("force"),
				})
			}

			opts := &app.CopyOptions{
				KVMount:    ctx.String("kv-mount"),
				SourcePath: from,
				DestPath:   to,
				Force:      ctx.Bool("force"),
			}

			return appInstance.Copy(opts)
		},
	}
}

func getListCommand() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Usage:   "List secrets at a path in Vault",
		Aliases: []string{"ls"},
		Description: `List secrets at a path in Vault's KV v2 secrets engine.

Directories are indicated with a trailing slash.

Examples:
  # List secrets at root
  vlt list

  # List secrets at a path
  vlt list --path secrets/myapp

  # List with custom KV mount
  vlt list --path myapp --kv-mount secret`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "path",
				Usage: "KV path to list (default: root)",
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
		},
		Action: func(ctx *cli.Context) error {
			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			opts := &app.ListOptions{
				KVMount: ctx.String("kv-mount"),
				Path:    ctx.String("path"),
			}

			keys, err := appInstance.List(opts)
			if err != nil {
				return err
			}

			if len(keys) == 0 {
				fmt.Fprintf(os.Stderr, "No secrets found at path: %s\n", opts.Path)
				return nil
			}

			for _, key := range keys {
				fmt.Println(key)
			}
			return nil
		},
	}
}

func getExportCommand() *cli.Command {
	return &cli.Command{
		Name:    "export",
		Usage:   "Export secrets from Vault to a file",
		Aliases: []string{"exp"},
		Description: `Export secrets from Vault to a file in JSON or .env format.

Examples:
  # Export as JSON to stdout
  vlt export --path secrets/myapp

  # Export as JSON to file
  vlt export --path secrets/myapp --output secrets.json

  # Export as .env format
  vlt export --path secrets/myapp --format env --output .env

  # Export with decryption
  vlt export --path secrets/myapp --encryption-key mykey --output secrets.json`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "path",
				Usage:    "KV path to export",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "output",
				Usage: "Output file path (default: stdout)",
				Value: "-",
			},
			&cli.StringFlag{
				Name:  "format",
				Usage: "Output format: json or env",
				Value: "json",
			},
			&cli.StringFlag{
				Name:  "encryption-key",
				Usage: "Transit encryption key for decryption",
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
			&cli.StringFlag{
				Name:  "transit-mount",
				Usage: "Transit mount path",
				Value: "transit",
			},
		},
		Action: func(ctx *cli.Context) error {
			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			opts := &app.ExportOptions{
				KVMount:       ctx.String("kv-mount"),
				Path:          ctx.String("path"),
				TransitMount:  ctx.String("transit-mount"),
				EncryptionKey: ctx.String("encryption-key"),
				Output:        ctx.String("output"),
				Format:        ctx.String("format"),
			}

			return appInstance.Export(opts)
		},
	}
}

func getImportCommand() *cli.Command {
	return &cli.Command{
		Name:    "import",
		Usage:   "Import secrets from a file to Vault",
		Aliases: []string{"imp"},
		Description: `Import secrets from a JSON or .env file to Vault.

The format is auto-detected based on file extension (.json or .env) or content.

Examples:
  # Import from JSON file
  vlt import --path secrets/myapp --input secrets.json

  # Import from .env file
  vlt import --path secrets/myapp --input .env

  # Import with encryption
  vlt import --path secrets/myapp --input secrets.json --encryption-key mykey

  # Import and merge with existing secrets
  vlt import --path secrets/myapp --input new-secrets.json --merge`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "path",
				Usage:    "KV path to import to",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "input",
				Usage:    "Input file path",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "format",
				Usage: "Input format: json or env (auto-detected if not specified)",
			},
			&cli.StringFlag{
				Name:  "encryption-key",
				Usage: "Transit encryption key for encryption",
			},
			&cli.BoolFlag{
				Name:  "merge",
				Usage: "Merge with existing secrets instead of replacing",
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
			&cli.StringFlag{
				Name:  "transit-mount",
				Usage: "Transit mount path",
				Value: "transit",
			},
		},
		Action: func(ctx *cli.Context) error {
			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			opts := &app.ImportOptions{
				KVMount:       ctx.String("kv-mount"),
				Path:          ctx.String("path"),
				TransitMount:  ctx.String("transit-mount"),
				EncryptionKey: ctx.String("encryption-key"),
				Input:         ctx.String("input"),
				Format:        ctx.String("format"),
				Merge:         ctx.Bool("merge"),
			}

			if err := appInstance.Import(opts); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Imported to: %s\n", opts.Path)
			return nil
		},
	}
}

func getSyncCommand() *cli.Command {
	return &cli.Command{
		Name:    "sync",
		Usage:   "Sync secrets from YAML config to .env file",
		Aliases: []string{"s"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "YAML config file",
				Value: ".vlt.yaml",
			},
			&cli.StringFlag{
				Name:  "output",
				Usage: "Output .env file",
				Value: ".env",
			},
		},
		Action: func(ctx *cli.Context) error {
			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			return appInstance.GenerateEnvFile(
				ctx.String("config"),
				ctx.String("output"),
				"", // encryption key will be taken from config or environment
			)
		},
	}
}

func getRunCommand() *cli.Command {
	return &cli.Command{
		Name:    "run",
		Usage:   "Run command with secrets injected as environment variables",
		Aliases: []string{"r"},
		Description: `Run a command with secrets from Vault injected as environment variables.

This command fetches secrets from Vault (using a config file or individual paths),
decrypts them if needed, and injects them into the environment of the specified command.

The command inherits your current environment and adds/overrides with Vault secrets.

Examples:
  # Run with config file (most common)
  vlt run --config secrets.yaml -- go run main.go
  
  # Run with default config file (.vlt.yaml)
  vlt run -- go run main.go
  
  # Run with inline secret injection
  vlt run --inject DB_PASSWORD=secrets/db_password -- ./myapp
  
  # Run with multiple secret injections
  vlt run --inject DB_PASSWORD=secrets/db_password --inject API_KEY=secrets/api_key -- npm start
  
  # Run with existing .env file plus Vault secrets
  vlt run --config secrets.yaml --env-file .env.local -- python app.py

Note: Use -- to separate vlt flags from the command to run.
Config search order: VLT_CONFIG env var, ./.vlt.yaml (current directory), ~/.vlt.yaml (global).
First found config will be used automatically if no --config is specified.`,
		ArgsUsage: "[-- command args...]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "YAML config file (search order: VLT_CONFIG env var, ./.vlt.yaml, ~/.vlt.yaml)",
			},
			&cli.StringFlag{
				Name:  "encryption-key",
				Usage: "Transit encryption key name",
			},
			&cli.StringSliceFlag{
				Name:  "inject",
				Usage: "Inject specific secret as ENV_VAR=vault_path (can be used multiple times)",
			},
			&cli.StringFlag{
				Name:  "env-file",
				Usage: "Load additional environment variables from .env file",
			},
			&cli.StringFlag{
				Name:  "kv-mount",
				Usage: "KV v2 mount path",
				Value: "home",
			},
			&cli.StringFlag{
				Name:  "transit-mount",
				Usage: "Transit mount path",
				Value: "transit",
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "Show environment variables that would be set without running the command",
			},
			&cli.BoolFlag{
				Name:  "preserve-env",
				Usage: "Preserve all current environment variables (default: true)",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "strict",
				Usage: "Fail if any secret cannot be loaded",
			},
			&cli.StringFlag{
				Name:  "prefix",
				Usage: "Prefix to add to all injected environment variable names",
			},
		},
		Action: func(ctx *cli.Context) error {
			// Check for default config file if none specified and no inject flags provided
			configFile := ctx.String("config")
			injectSecrets := ctx.StringSlice("inject")

			if configFile == "" && len(injectSecrets) == 0 {
				// Check for default config file (current directory, then global)
				configFile = findConfigFile()
			}

			// Validate that we have either config or inject flags
			if configFile == "" && len(injectSecrets) == 0 {
				return fmt.Errorf("either --config, config file (VLT_CONFIG env, ./.vlt.yaml, ~/.vlt.yaml), or --inject must be specified")
			}

			// Get the command to run (everything after --)
			args := ctx.Args().Slice()
			if len(args) == 0 {
				return fmt.Errorf("command to run is required. Use -- to separate vlt options from the command")
			}

			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			opts := &app.RunOptions{
				KVMount:       ctx.String("kv-mount"),
				TransitMount:  ctx.String("transit-mount"),
				EncryptionKey: ctx.String("encryption-key"),
				ConfigFile:    configFile,
				InjectSecrets: injectSecrets,
				EnvFile:       ctx.String("env-file"),
				DryRun:        ctx.Bool("dry-run"),
				PreserveEnv:   ctx.Bool("preserve-env"),
				Command:       args[0],
				Args:          args[1:],
				Strict:        ctx.Bool("strict"),
				Prefix:        ctx.String("prefix"),
			}

			return appInstance.Run(opts)
		},
	}
}

func getJSONCommand() *cli.Command {
	return &cli.Command{
		Name:    "json",
		Usage:   "Encrypt .env file content and output as JSON",
		Aliases: []string{"j"},
		Description: `Encrypts environment variables from a .env file using Vault Transit encryption and outputs the result as JSON.

This command is useful for converting .env files to encrypted JSON format that can be stored in Vault or other secure storage systems.

Encryption is controlled by:
  1. TRANSIT environment variable (true/false, 1/0, yes/no, on/off, enable/disable)
  2. --encryption-key flag or ENCRYPTION_KEY environment variable

Defaults when TRANSIT=true:
  - ENCRYPTION_KEY defaults to "app-secrets"
  - TRANSIT_MOUNT defaults to "transit"

Examples:
  # Output plaintext JSON (default behavior)
  vlt json
  
  # Output plaintext JSON from specific file
  vlt json example.env
  
  # Enable encryption with defaults (key="app-secrets", mount="transit")
  TRANSIT=true vlt json
  
  # Enable encryption with custom key
  TRANSIT=true ENCRYPTION_KEY=mykey vlt json
  
  # Enable encryption with command flag
  vlt json --encryption-key mykey
  
  # Disable encryption even if encryption key is set
  TRANSIT=false ENCRYPTION_KEY=mykey vlt json
  
  # Use custom transit mount
  TRANSIT=true TRANSIT_MOUNT=custom-transit vlt json example.env`,
		ArgsUsage: "[env-file]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "encryption-key",
				Usage: "Transit encryption key name (optional - if not provided, outputs plaintext)",
			},
			&cli.StringFlag{
				Name:  "transit-mount",
				Usage: "Transit mount path",
				Value: "transit",
			},
		},
		Action: func(ctx *cli.Context) error {
			// Get env file from args or default to .env
			envFile := ctx.Args().First()
			if envFile == "" {
				envFile = ".env"
			}

			// Check if encryption is needed based on encryption key and TRANSIT env var
			encryptionKey := config.GetEncryptionKey(ctx.String("encryption-key"))
			useEncryption := config.ShouldUseEncryption(encryptionKey)

			if !useEncryption {
				// For plaintext output, don't need vault client
				return handlePlaintextJSON(envFile)
			}

			// For encryption, create app with vault client
			appInstance, err := app.New()
			if err != nil {
				return fmt.Errorf("failed to create app: %w", err)
			}

			opts := &app.JSONOptions{
				TransitMount:  config.GetTransitMount(ctx.String("transit-mount")),
				EncryptionKey: ctx.String("encryption-key"),
				EnvFile:       envFile,
			}

			return appInstance.JSON(opts)
		},
	}
}

// findConfigFile searches for config in order: env var, .vlt.yaml (current dir), ~/.vlt.yaml (global)
func findConfigFile() string {
	// First check environment variable
	if envConfig := os.Getenv("VLT_CONFIG"); envConfig != "" {
		if _, err := os.Stat(envConfig); err == nil {
			return envConfig
		}
	}

	// Check current directory for .vlt.yaml
	if _, err := os.Stat(".vlt.yaml"); err == nil {
		return ".vlt.yaml"
	}

	// Check global config in home directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		globalConfig := homeDir + "/.vlt.yaml"
		if _, err := os.Stat(globalConfig); err == nil {
			return globalConfig
		}
	}

	return ""
}

// handlePlaintextJSON handles JSON output without encryption (no vault client needed)
func handlePlaintextJSON(envFile string) error {
	// Check if file exists
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		return fmt.Errorf("env file not found: %s", envFile)
	}

	// Load as plaintext
	data, err := utils.LoadEnvFileAsPlaintext(envFile)
	if err != nil {
		return fmt.Errorf("load env file: %w", err)
	}

	// Output as JSON
	if err := utils.OutputJSON(data); err != nil {
		return fmt.Errorf("output json: %w", err)
	}

	return nil
}

func getCompletionCommand() *cli.Command {
	return &cli.Command{
		Name:  "completion",
		Usage: "Generate shell completion scripts",
		Description: `Generate shell completion scripts for various shells.

Supported shells: bash, zsh, fish, powershell

To install completions:

Bash:
  vlt completion bash > /etc/bash_completion.d/vlt
  # Or for user-only:
  vlt completion bash > ~/.bash_completion.d/vlt

Zsh:
  vlt completion zsh > /usr/local/share/zsh/site-functions/_vlt
  # Or for user-only:
  vlt completion zsh > ~/.zsh/completions/_vlt

Fish:
  vlt completion fish > ~/.config/fish/completions/vlt.fish

PowerShell:
  vlt completion powershell > vlt.ps1
  # Then source it in your PowerShell profile`,
		Aliases:   []string{"comp"},
		ArgsUsage: "[shell]",
		Action: func(ctx *cli.Context) error {
			shell := ctx.Args().First()
			if shell == "" {
				return fmt.Errorf("shell argument required. Supported: bash, zsh, fish, powershell")
			}

			// Generate completion script for the specified shell
			switch shell {
			case "bash":
				return generateBashCompletion(ctx)
			case "zsh":
				return generateZshCompletion(ctx)
			case "fish":
				return generateFishCompletion(ctx)
			case "powershell":
				return generatePowerShellCompletion(ctx)
			default:
				return fmt.Errorf("unsupported shell: %s. Supported: bash, zsh, fish, powershell", shell)
			}
		},
	}
}

// Completion generation functions
func generateBashCompletion(ctx *cli.Context) error {
	_, err := fmt.Print(`# vlt bash completion
_vlt_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Complete commands
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        opts="put get delete list copy export import sync run json completion help"
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
    
    # Complete flags based on command
    case "${COMP_WORDS[1]}" in
        put|p)
            opts="--path --encryption-key --key --value --from-env --from-file --kv-mount --transit-mount --help"
            ;;
        get|g)
            opts="--path --config --encryption-key --key --json --kv-mount --transit-mount --help"
            ;;
        delete|d|rm)
            opts="--path --kv-mount --help"
            ;;
        list|ls)
            opts="--path --kv-mount --help"
            ;;
        copy|c|cp)
            opts="--from --to --config --kv-mount --force --help"
            ;;
        export|exp)
            opts="--path --output --format --encryption-key --kv-mount --transit-mount --help"
            ;;
        import|imp)
            opts="--path --input --format --encryption-key --merge --kv-mount --transit-mount --help"
            ;;
        sync|s)
            opts="--config --output --help"
            ;;
        run|r)
            opts="--config --encryption-key --inject --env-file --kv-mount --transit-mount --dry-run --preserve-env --help"
            ;;
        json|j)
            opts="--encryption-key --transit-mount --help"
            ;;
        completion|comp)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- ${cur}) )
                return 0
            fi
            ;;
        *)
            opts="--help"
            ;;
    esac
    
    # Complete file paths for certain flags
    if [[ "$prev" == "--from-env" || "$prev" == "--from-file" || "$prev" == "--config" ]]; then
        COMPREPLY=( $(compgen -f -- ${cur}) )
        return 0
    fi
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
}

complete -F _vlt_completion vlt
`)
	return err
}

func generateZshCompletion(ctx *cli.Context) error {
	_, err := fmt.Print(`#compdef vlt

_vlt() {
    local context curcontext state line
    typeset -A opt_args
    
    _arguments -C \
        '1: :_vlt_commands' \
        '*:: :->args'
    
    case $state in
        args)
            case $words[1] in
                put|p)
                    _arguments \
                        '--path=[KV path to store secret(s)]:path:' \
                        '--encryption-key=[Transit encryption key name]:key:' \
                        '--key=[Specific key to update]:key:' \
                        '--value=[Secret value]:value:' \
                        '--from-env=[Load from .env file]:file:_files' \
                        '--from-file=[Load file as base64]:file:_files' \
                        '--kv-mount=[KV v2 mount path]:mount:' \
                        '--transit-mount=[Transit mount path]:mount:' \
                        '--help[Show help]'
                    ;;
                get|g)
                    _arguments \
                        '--path=[KV path to retrieve secret]:path:' \
                        '--config=[YAML config file]:file:_files' \
                        '--encryption-key=[Transit encryption key name]:key:' \
                        '--key=[Specific key to retrieve]:key:' \
                        '--json[Output as JSON format]' \
                        '--kv-mount=[KV v2 mount path]:mount:' \
                        '--transit-mount=[Transit mount path]:mount:' \
                        '--help[Show help]'
                    ;;
                delete|d|rm)
                    _arguments \
                        '--path=[KV path of secret to delete]:path:' \
                        '--kv-mount=[KV v2 mount path]:mount:' \
                        '--help[Show help]'
                    ;;
                list|ls)
                    _arguments \
                        '--path=[KV path to list]:path:' \
                        '--kv-mount=[KV v2 mount path]:mount:' \
                        '--help[Show help]'
                    ;;
                copy|c|cp)
                    _arguments \
                        '--from=[Source KV path to copy from]:path:' \
                        '--to=[Destination KV path to copy to]:path:' \
                        '--config=[YAML config file with copy pairs]:file:_files' \
                        '--kv-mount=[KV v2 mount path]:mount:' \
                        '--force[Overwrite if destination exists]' \
                        '--help[Show help]'
                    ;;
                sync|s)
                    _arguments \
                        '--config=[YAML config file]:file:_files' \
                        '--output=[Output .env file]:file:_files' \
                        '--help[Show help]'
                    ;;
                run|r)
                    _arguments \
                        '--config=[YAML config file]:file:_files' \
                        '--encryption-key=[Transit encryption key name]:key:' \
                        '--inject=[Inject specific secret]:inject:' \
                        '--env-file=[Additional .env file]:file:_files' \
                        '--kv-mount=[KV v2 mount path]:mount:' \
                        '--transit-mount=[Transit mount path]:mount:' \
                        '--dry-run[Show env vars without running]' \
                        '--preserve-env[Preserve current environment]' \
                        '--help[Show help]'
                    ;;
                json|j)
                    _arguments \
                        '--encryption-key=[Transit encryption key name]:key:' \
                        '--transit-mount=[Transit mount path]:mount:' \
                        '--help[Show help]' \
                        '1: :_files'
                    ;;
                completion|comp)
                    _arguments '1: :(bash zsh fish powershell)'
                    ;;
            esac
            ;;
    esac
}

_vlt_commands() {
    local -a commands
    commands=(
        'put:Store/update secrets in Vault'
        'get:Retrieve and decrypt secrets from Vault'
        'delete:Delete a secret from Vault'
        'list:List secrets at a path in Vault'
        'copy:Copy secrets from one path to another'
        'export:Export secrets from Vault to a file'
        'import:Import secrets from a file to Vault'
        'sync:Sync secrets from YAML config to .env file'
        'run:Run command with secrets injected as environment variables'
        'json:Encrypt .env file content and output as JSON'
        'completion:Generate shell completion scripts'
        'help:Show help'
    )
    _describe 'commands' commands
}

_vlt
`)
	return err
}

func generateFishCompletion(ctx *cli.Context) error {
	_, err := fmt.Print(`# vlt fish completion

# Commands
complete -c vlt -f -n '__fish_use_subcommand' -a 'put' -d 'Store/update secrets in Vault'
complete -c vlt -f -n '__fish_use_subcommand' -a 'get' -d 'Retrieve and decrypt secrets from Vault'
complete -c vlt -f -n '__fish_use_subcommand' -a 'sync' -d 'Sync secrets from YAML config to .env file'
complete -c vlt -f -n '__fish_use_subcommand' -a 'run' -d 'Run command with secrets injected as environment variables'
complete -c vlt -f -n '__fish_use_subcommand' -a 'json' -d 'Encrypt .env file content and output as JSON'
complete -c vlt -f -n '__fish_use_subcommand' -a 'completion' -d 'Generate shell completion scripts'
complete -c vlt -f -n '__fish_use_subcommand' -a 'copy' -d 'Copy secrets from one path to another'
complete -c vlt -f -n '__fish_use_subcommand' -a 'help' -d 'Show help'

# Aliases
complete -c vlt -f -n '__fish_use_subcommand' -a 'p' -d 'Store/update secrets in Vault (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'g' -d 'Retrieve and decrypt secrets from Vault (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'd' -d 'Delete a secret from Vault (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'rm' -d 'Delete a secret from Vault (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'ls' -d 'List secrets at a path in Vault (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'c' -d 'Copy secrets from one path to another (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'cp' -d 'Copy secrets from one path to another (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'exp' -d 'Export secrets from Vault to a file (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'imp' -d 'Import secrets from a file to Vault (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 's' -d 'Sync secrets from YAML config to .env file (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'r' -d 'Run command with secrets injected as environment variables (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'j' -d 'Encrypt .env file content and output as JSON (alias)'
complete -c vlt -f -n '__fish_use_subcommand' -a 'comp' -d 'Generate shell completion scripts (alias)'

# Put command options
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'path' -d 'KV path to store secret(s)'
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'encryption-key' -d 'Transit encryption key name'
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'key' -d 'Specific key to update in multi-value secret'
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'value' -d 'Secret value'
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'from-env' -d 'Load multiple key-value pairs from .env file'
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'from-file' -d 'Load file content as base64 encoded value'
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'kv-mount' -d 'KV v2 mount path'
complete -c vlt -f -n '__fish_seen_subcommand_from put p' -l 'transit-mount' -d 'Transit mount path'

# Copy command options
complete -c vlt -f -n '__fish_seen_subcommand_from copy c cp' -l 'from' -d 'Source KV path to copy from'
complete -c vlt -f -n '__fish_seen_subcommand_from copy c cp' -l 'to' -d 'Destination KV path to copy to'
complete -c vlt -f -n '__fish_seen_subcommand_from copy c cp' -l 'config' -d 'YAML config file with copy pairs'
complete -c vlt -f -n '__fish_seen_subcommand_from copy c cp' -l 'kv-mount' -d 'KV v2 mount path'
complete -c vlt -f -n '__fish_seen_subcommand_from copy c cp' -l 'force' -d 'Overwrite if destination exists'

# Get command options
complete -c vlt -f -n '__fish_seen_subcommand_from get g' -l 'path' -d 'KV path to retrieve secret'
complete -c vlt -f -n '__fish_seen_subcommand_from get g' -l 'config' -d 'YAML config file with secret definitions'
complete -c vlt -f -n '__fish_seen_subcommand_from get g' -l 'encryption-key' -d 'Transit encryption key name'
complete -c vlt -f -n '__fish_seen_subcommand_from get g' -l 'key' -d 'Specific key to retrieve'
complete -c vlt -f -n '__fish_seen_subcommand_from get g' -l 'json' -d 'Output as JSON format'
complete -c vlt -f -n '__fish_seen_subcommand_from get g' -l 'kv-mount' -d 'KV v2 mount path'
complete -c vlt -f -n '__fish_seen_subcommand_from get g' -l 'transit-mount' -d 'Transit mount path'

# Sync command options
complete -c vlt -f -n '__fish_seen_subcommand_from sync s' -l 'config' -d 'YAML config file'
complete -c vlt -f -n '__fish_seen_subcommand_from sync s' -l 'output' -d 'Output .env file'

# Run command options
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'config' -d 'YAML config file with secret definitions'
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'encryption-key' -d 'Transit encryption key name'
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'inject' -d 'Inject specific secret as ENV_VAR=vault_path'
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'env-file' -d 'Load additional environment variables from .env file'
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'kv-mount' -d 'KV v2 mount path'
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'transit-mount' -d 'Transit mount path'
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'dry-run' -d 'Show environment variables without running command'
complete -c vlt -f -n '__fish_seen_subcommand_from run r' -l 'preserve-env' -d 'Preserve all current environment variables'

# JSON command options
complete -c vlt -f -n '__fish_seen_subcommand_from json j' -l 'encryption-key' -d 'Transit encryption key name'
complete -c vlt -f -n '__fish_seen_subcommand_from json j' -l 'transit-mount' -d 'Transit mount path'

# Completion command options
complete -c vlt -f -n '__fish_seen_subcommand_from completion comp' -a 'bash' -d 'Generate bash completion'
complete -c vlt -f -n '__fish_seen_subcommand_from completion comp' -a 'zsh' -d 'Generate zsh completion'
complete -c vlt -f -n '__fish_seen_subcommand_from completion comp' -a 'fish' -d 'Generate fish completion'
complete -c vlt -f -n '__fish_seen_subcommand_from completion comp' -a 'powershell' -d 'Generate PowerShell completion'

# Global options
complete -c vlt -f -l 'vault-addr' -d 'Vault server address'
complete -c vlt -f -l 'vault-token' -d 'Vault authentication token'
complete -c vlt -f -l 'vault-namespace' -d 'Vault namespace'
complete -c vlt -f -l 'encryption-key' -d 'Default transit encryption key'
complete -c vlt -f -l 'help' -d 'Show help'
complete -c vlt -f -l 'version' -d 'Print version'
`)
	return err
}

func generatePowerShellCompletion(ctx *cli.Context) error {
	_, err := fmt.Print(`# vlt PowerShell completion

Register-ArgumentCompleter -Native -CommandName vlt -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    
    $commands = @('put', 'get', 'delete', 'list', 'copy', 'export', 'import', 'sync', 'run', 'json', 'completion', 'help')
    $aliases = @('p', 'g', 'd', 'rm', 'ls', 'c', 'cp', 'exp', 'imp', 's', 'r', 'j', 'comp', 'h')
    
    # Split the command line
    $commandElements = $wordToComplete.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
    
    # Complete main commands
    if ($commandElements.Count -le 1) {
        return ($commands + $aliases) | Where-Object { $_ -like "$wordToComplete*" }
    }
    
    # Complete based on subcommand
    switch ($commandElements[0]) {
        { $_ -in @('put', 'p') } {
            return @('--path', '--encryption-key', '--key', '--value', '--from-env', '--from-file', '--kv-mount', '--transit-mount', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('get', 'g') } {
            return @('--path', '--config', '--encryption-key', '--key', '--json', '--kv-mount', '--transit-mount', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('delete', 'd', 'rm') } {
            return @('--path', '--kv-mount', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('list', 'ls') } {
            return @('--path', '--kv-mount', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('copy', 'c', 'cp') } {
            return @('--from', '--to', '--config', '--kv-mount', '--force', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('export', 'exp') } {
            return @('--path', '--output', '--format', '--encryption-key', '--kv-mount', '--transit-mount', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('import', 'imp') } {
            return @('--path', '--input', '--format', '--encryption-key', '--merge', '--kv-mount', '--transit-mount', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('sync', 's') } {
            return @('--config', '--output', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('run', 'r') } {
            return @('--config', '--encryption-key', '--inject', '--env-file', '--kv-mount', '--transit-mount', '--dry-run', '--preserve-env', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('json', 'j') } {
            return @('--encryption-key', '--transit-mount', '--help') | Where-Object { $_ -like "$wordToComplete*" }
        }
        { $_ -in @('completion', 'comp') } {
            return @('bash', 'zsh', 'fish', 'powershell') | Where-Object { $_ -like "$wordToComplete*" }
        }
    }
    
    return @()
}
`)
	return err
}
