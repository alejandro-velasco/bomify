package scan

import (
	"fmt"

	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// Input scans the component whose files bomify pulled into dir: it
// catalogs them with syft — a Go or Rust binary's embedded module list,
// a Java archive's manifest, a known binary's version string, any
// package metadata among them — and matches every package found against
// provider, reporting them as buildCatalogResult does. If syft finds no
// package at all, the result says the component couldn't be analyzed
// (SecurityResult.Unscanned) rather than reporting it clean.
func Input(provider vulnerability.Provider, dir string) (pluginlib.SecurityResult, error) {
	packages, pkgContext, err := catalogFiles(dir)
	if err != nil {
		return pluginlib.SecurityResult{}, err
	}
	if len(packages) == 0 {
		return pluginlib.SecurityResult{Unscanned: "syft found no packages in its files"}, nil
	}

	matches, err := findMatches(provider, packages, pkgContext)
	if err != nil {
		return pluginlib.SecurityResult{}, fmt.Errorf("find matches in %s: %w", dir, err)
	}
	return buildCatalogResult(packages, matches), nil
}

// catalogFiles catalogs the files in dir with syft, through grype's own
// syft-backed provider as scanImage does, with a "dir:" source.
func catalogFiles(dir string) ([]grypePkg.Package, grypePkg.Context, error) {
	cfg := grypePkg.ProviderConfig{
		SyftProviderConfig: grypePkg.SyftProviderConfig{
			SBOMOptions: syft.DefaultCreateSBOMConfig(),
		},
	}
	packages, pkgContext, _, err := grypePkg.Provide("dir:"+dir, cfg)
	if err != nil {
		return nil, grypePkg.Context{}, fmt.Errorf("catalog %s: %w", dir, err)
	}
	return packages, pkgContext, nil
}
