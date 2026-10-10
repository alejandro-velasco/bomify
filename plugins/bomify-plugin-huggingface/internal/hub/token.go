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

// Environment variables hf itself reads too.
const (
	// tokenEnv holds a hub access token.
	tokenEnv = "HF_TOKEN"
	// endpointEnv holds the hub's address.
	endpointEnv = "HF_ENDPOINT"
	// tokenPathEnv holds the path of the token "hf auth login" stored.
	tokenPathEnv = "HF_TOKEN_PATH"
	// homeEnv holds hf's home directory, which holds that token.
	homeEnv = "HF_HOME"
	// cacheHomeEnv holds the user's cache directory, hf's home's parent.
	cacheHomeEnv = "XDG_CACHE_HOME"
)

// lookupCredentials is pkg/auth's Get, replaced in tests.
var lookupCredentials = auth.Get

// resolveEndpoint returns the hub to use: endpoint, else $HF_ENDPOINT,
// else huggingface.co. It must be an http or https URL with a host.
func resolveEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" {
		endpoint = os.Getenv(endpointEnv)
	}
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	hub, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse hub address %q: %w", endpoint, err)
	}
	if hub.Scheme != "https" && hub.Scheme != "http" {
		return nil, fmt.Errorf("hub address %q isn't an http or https URL, e.g. %s", endpoint, DefaultEndpoint)
	}
	if hub.Host == "" {
		return nil, fmt.Errorf("hub address %q has no host, e.g. %s", endpoint, DefaultEndpoint)
	}
	hub.Path = strings.TrimSuffix(hub.Path, "/")
	return hub, nil
}

// Token returns the access token for the hub at endpoint (see
// resolveEndpoint), or "" for none: $HF_TOKEN, else the token
// "bomify login <hub host> --verify=false" stored for the hub's host,
// else the one "hf auth login" stored.
func Token(endpoint string, logger *slog.Logger) (string, error) {
	if token := os.Getenv(tokenEnv); token != "" {
		return token, nil
	}

	hub, err := resolveEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	_, token, err := lookupCredentials(hub.Host)
	if err != nil {
		return "", fmt.Errorf("look up credentials for %s: %w", hub.Host, err)
	}
	if token != "" {
		logger.Info("using the token bomify login stored", "host", hub.Host)
		return token, nil
	}

	return hfLoginToken(logger)
}

// hfLoginToken returns the token "hf auth login" stored, where hf itself
// looks for it: $HF_TOKEN_PATH, else "token" under $HF_HOME, else under
// $XDG_CACHE_HOME/huggingface or ~/.cache/huggingface.
func hfLoginToken(logger *slog.Logger) (string, error) {
	var path string
	if tokenPath := os.Getenv(tokenPathEnv); tokenPath != "" {
		path = tokenPath
	} else if home := os.Getenv(homeEnv); home != "" {
		path = filepath.Join(home, "token")
	} else if cache := os.Getenv(cacheHomeEnv); cache != "" {
		path = filepath.Join(cache, "huggingface", "token")
	} else if userHome, err := os.UserHomeDir(); err == nil {
		path = filepath.Join(userHome, ".cache", "huggingface", "token")
	} else {
		return "", nil
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
