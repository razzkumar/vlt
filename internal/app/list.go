package app

import (
	"fmt"
)

// ListOptions contains options for the List operation
type ListOptions struct {
	KVMount string
	Path    string
}

// List lists secrets at a path in Vault
func (a *App) List(opts *ListOptions) ([]string, error) {
	kvMount := opts.KVMount
	if kvMount == "" {
		kvMount = "home"
	}

	path := opts.Path
	if path == "" {
		path = "/"
	}

	keys, err := a.vaultClient.KVList(kvMount, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	return keys, nil
}
