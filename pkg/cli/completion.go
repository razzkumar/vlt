package cli

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

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
