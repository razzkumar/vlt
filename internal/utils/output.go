package utils

import (
	"encoding/json"
	"fmt"
)

// OutputJSON outputs data as formatted JSON
func OutputJSON(data map[string]any) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

// OutputEnvFormat outputs data in .env format
func OutputEnvFormat(data map[string]any) {
	for k, v := range data {
		fmt.Printf("%s=%v\n", k, v)
	}
}

// MergeData merges new data into existing data, preserving existing values and adding/updating new ones
func MergeData(existing, new map[string]any) map[string]any {
	result := make(map[string]any)

	// Copy existing data
	for k, v := range existing {
		result[k] = v
	}

	// Add/update with new data
	for k, v := range new {
		result[k] = v
	}

	return result
}
