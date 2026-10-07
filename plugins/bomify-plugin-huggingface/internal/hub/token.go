package hub

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/alejandro-velasco/bomify/pkg/auth"
)

// lookupCredentials is pkg/auth's Get, replaced in tests.
var lookupCredentials = auth.Get

// resolveEndpoint returns the hub to use: endpoint, else $HF_ENDPOINT,
// else huggingface.co.
func resolveEndpoint(endpoint string) string {
	if endpoint == "" {
		endpoint = os.Getenv("HF_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "https://" + DefaultHost
	}
	return strings.TrimSuffix(endpoint, "/")
}

// Token returns the access token for the hub at endpoint (see
// resolveEndpoint), or "" for none: $HF_TOKEN, else the token
// "bomify login <hub host> --verify=false" stored for the hub's host,
// else the one "hf auth login" stored.
func Token(endpoint string, logger *slog.Logger) (string, error) {
	if token := os.Getenv("HF_TOKEN"); token != "" {
		return token, nil
	}

	parsed, err := url.Parse(resolveEndpoint(endpoint))
	if err != nil {
		return "", fmt.Errorf("parse hub address %q: %w", endpoint, err)
	}
	_, token, err := lookupCredentials(parsed.Host)
	if err != nil {
		return "", fmt.Errorf("look up credentials for %s: %w", parsed.Host, err)
	}
	if token != "" {
		logger.Info("using the token bomify login stored", "host", parsed.Host)
		return token, nil
	}

	return hfLoginToken(logger)
}

// hfLoginToken returns the token "hf auth login" stored, where hf itself
// looks for it: $HF_TOKEN_PATH, else "token" under $HF_HOME, else under
// $XDG_CACHE_HOME/huggingface or ~/.cache/huggingface.
func hfLoginToken(logger *slog.Logger) (string, error) {
	path := os.Getenv("HF_TOKEN_PATH")
	if path == "" {
		home := os.Getenv("HF_HOME")
		if home == "" {
			cache := os.Getenv("XDG_CACHE_HOME")
			if cache == "" {
				userHome, err := os.UserHomeDir()
				if err != nil {
					return "", nil
				}
				cache = filepath.Join(userHome, ".cache")
			}
			home = filepath.Join(cache, "huggingface")
		}
		path = filepath.Join(home, "token")
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read hf's token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token != "" {
		logger.Info("using the token hf auth login stored", "path", path)
	}
	return token, nil
}
