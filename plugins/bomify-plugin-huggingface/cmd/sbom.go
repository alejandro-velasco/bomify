package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-huggingface/internal/hub"
)

// defaultConfigPath is "sbom generate"'s --config default: read if
// present in the working directory, skipped if not.
const defaultConfigPath = "bomify-huggingface-sbom.yaml"

// options is "sbom generate"'s options object, --config's keys (see
// generateLong).
type options struct {
	Model         string `json:"model"`
	Revision      string `json:"revision,omitempty"`
	RepositoryURL string `json:"repository-url,omitempty"`
}

// sbomCmd implements the SBOM generation plugin contract (see
// plugins/contracts/sbom/v1/CONTRACT.md), kept independent of this
// binary's component contract commands.
func sbomCmd() *cobra.Command {
	help := plugin.SBOMHelp{
		Generate:      "Describe a Hugging Face Hub model, pinned to a commit, with its hash and model card",
		Long:          generateLong,
		DefaultConfig: defaultConfigPath,
	}
	return plugin.SBOMCommand(sbomGenerator{}, help)
}

const generateLong = `Generate describes a Hugging Face Hub model as a CycloneDX SBOM (JSON)
printed to stdout (--output redirects it to a file instead): one
machine-learning-model component, both what the SBOM describes and what
"bomify build" packages, with a pkg:huggingface purl pinned to the
commit the revision resolves to, so builds from it are reproducible.

Its SHA-256 is the tree hash "component pull" reports, computed from the
Hub's file listing: only files stored in Git, which are small, are
downloaded, never the weights. Its model card records the Hub's task,
architecture, and training datasets, as data rather than components to
package; its licenses, supplier, and base model come from the model
card's metadata too.

The model is described by --config, an options file, JSON or YAML.
Without --config, "bomify-huggingface-sbom.yaml" is read from the working
directory if present. Its keys, of which only model is required:

  model            the model repository, <namespace>/<name>
  revision         branch, tag, or commit; "main" if omitted
  repository-url   another hub, e.g. https://hub.example.com, recorded
                   as the purl's repository_url; $HF_ENDPOINT, or
                   huggingface.co, if omitted

A gated or private model needs a token: $HF_TOKEN, else one stored with
"bomify login <hub host> --verify=false", else "hf auth login"'s.`

// sbomGenerator implements plugin.SBOMPlugin over internal/hub.
type sbomGenerator struct{}

func (sbomGenerator) Generate(ctx context.Context, raw json.RawMessage, logger *slog.Logger) (*cdx.BOM, error) {
	var config options
	if err := plugin.DecodeOptions(raw, &config); err != nil {
		return nil, err
	}
	if config.Model == "" {
		return nil, errors.New(`required "model" not set in the options`)
	}

	client, err := hub.NewClient(config.RepositoryURL, logger)
	if err != nil {
		return nil, err
	}
	generate := hub.GenerateOptions{
		RepoID:        config.Model,
		Revision:      config.Revision,
		RepositoryURL: config.RepositoryURL,
	}
	return hub.Generate(ctx, client, generate, logger)
}
