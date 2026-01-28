package app

import (
	"fmt"

	"github.com/razzkumar/vlt/internal/utils"
	"github.com/razzkumar/vlt/pkg/config"
	"github.com/razzkumar/vlt/pkg/vault"
)

// App represents the main application
type App struct {
	vaultClient vault.VaultClient
}

// New creates a new application instance
func New() (*App, error) {
	vaultConfig := config.GetVaultConfigFromEnv()
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, utils.EnhanceError(fmt.Errorf("failed to create vault client: %w", err))
	}

	return &App{
		vaultClient: client,
	}, nil
}

// NewWithClient creates an App with a provided VaultClient (for testing)
func NewWithClient(client vault.VaultClient) *App {
	return &App{
		vaultClient: client,
	}
}

// NewWithOverrides creates a new application instance with config overrides
// This allows CLI flags to take precedence over environment variables
func NewWithOverrides(overrides *config.VaultConfigOverrides) (*App, error) {
	vaultConfig := config.GetVaultConfigWithOverrides(overrides)
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, utils.EnhanceError(fmt.Errorf("failed to create vault client: %w", err))
	}

	return &App{
		vaultClient: client,
	}, nil
}
