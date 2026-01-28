package app

import (
	"fmt"
)

// DeleteOptions contains options for the Delete operation
type DeleteOptions struct {
	KVMount string
	Path    string
}

// Delete deletes a secret from Vault
func (a *App) Delete(opts *DeleteOptions) error {
	if opts.Path == "" {
		return fmt.Errorf("path is required")
	}

	kvMount := opts.KVMount
	if kvMount == "" {
		kvMount = "home"
	}

	err := a.vaultClient.KVDelete(kvMount, opts.Path)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}
