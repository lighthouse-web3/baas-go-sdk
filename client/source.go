package client

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

func getOrGenerateSourceID() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(home, ".lighthouse", "baas")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}

	idFile := filepath.Join(configDir, "source_id")
	data, err := os.ReadFile(idFile)
	if err == nil {
		id := string(data)
		if len(id) > 0 {
			return id, nil
		}
	}

	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	newID := hex.EncodeToString(bytes)

	if err := os.WriteFile(idFile, []byte(newID), 0600); err != nil {
		return "", err
	}

	return newID, nil
}
