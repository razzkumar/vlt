package app

import (
	"fmt"

	"github.com/razzkumar/vlt/pkg/config"
	"github.com/razzkumar/vlt/pkg/vault"
)

// App represents the main application
type App struct {
	vaultClient *vault.Client
}

// New creates a new application instance
func New() (*App, error) {
	vaultConfig := config.GetVaultConfigFromEnv()
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	return &App{
		vaultClient: client,
	}, nil
}
