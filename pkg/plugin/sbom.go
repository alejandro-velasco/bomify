package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"sigs.k8s.io/yaml"
)

// SBOMPlugin is an SBOM generation plugin's own logic (see
// plugins/contracts/sbom/v1/CONTRACT.md), for SBOMCommand to expose as
// the contract's "sbom schema"/"sbom generate".
type SBOMPlugin interface {
	// OptionsSchema returns the JSON Schema of the options object Generate
	// takes, which "sbom schema" prints.
	OptionsSchema() []byte
	// Generate generates the SBOM options describe. Decode options with
	// DecodeOptions, so unknown keys are rejected.
	Generate(ctx context.Context, options json.RawMessage, logger *slog.Logger) (*cdx.BOM, error)
}

// SBOMHelp is the plugin-specific help, and direct-use interface,
// SBOMCommand adds.
type SBOMHelp struct {
	// Generate is "sbom generate"'s short description, and Long its long
	// one.
	Generate, Long string
	// DefaultConfig, if set, is --config's default: read if it exists,
	// skipped if it doesn't, unlike a --config given explicitly.
	DefaultConfig string
	// Flags, if set, adds the plugin's own flags for running "sbom
	// generate" directly, returning how to apply them, once parsed, over
	// the options --config gave ("{}" if none).
	Flags func(flags *pflag.FlagSet) func(options json.RawMessage) (json.RawMessage, error)
}

// SBOMCommand builds the "sbom" command implementing the SBOM generation
// plugin contract around p. Its "generate" reads --config as JSON or
// YAML, and refuses to print an SBOM that breaks the contract's output
// rules (see ValidateGenerated).
func SBOMCommand(p SBOMPlugin, help SBOMHelp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   SBOMSubcommand,
		Short: "SBOM generation subcommands — see plugins/contracts/sbom/v1/CONTRACT.md",
	}

	schema := &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema of the options \"sbom generate --config\" takes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := cmd.OutOrStdout().Write(p.OptionsSchema())
			return err
		},
	}

	var config, output string
	var apply func(json.RawMessage) (json.RawMessage, error)
	generate := &cobra.Command{
		Use:   "generate",
		Short: help.Generate,
		Long:  help.Long,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := readOptions(config, cmd.Flags().Changed("config"))
			if err != nil {
				return err
			}
			if apply != nil {
				if options, err = apply(options); err != nil {
					return err
				}
			}

			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
			bom, err := p.Generate(cmd.Context(), options, logger)
			if err != nil {
				return err
			}
			if err := ValidateGenerated(bom); err != nil {
				return fmt.Errorf("generated SBOM breaks the SBOM contract: %w", err)
			}

			if output == "" {
				return EncodeSBOM(cmd.OutOrStdout(), bom)
			}
			f, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("create %s: %w", output, err)
			}
			if err := EncodeSBOM(f, bom); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		},
	}
	generate.Flags().StringVar(&config, "config", help.DefaultConfig, "the options, a JSON or YAML file (see \"sbom schema\")")
	generate.Flags().StringVarP(&output, "output", "o", "", "write the SBOM to this file instead of stdout")
	if help.Flags != nil {
		apply = help.Flags(generate.Flags())
	}

	cmd.AddCommand(schema, generate)
	return cmd
}

// readOptions reads the options file at path as JSON, converting it from
// YAML if need be, or returns "{}" when there's none: path is empty, or
// is missing and wasn't given explicitly.
func readOptions(path string, explicit bool) (json.RawMessage, error) {
	if path == "" {
		return json.RawMessage("{}"), nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return json.RawMessage("{}"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read options: %w", err)
	}
	options, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse options %s: %w", path, err)
	}
	if bytes.Equal(bytes.TrimSpace(options), []byte("null")) {
		return json.RawMessage("{}"), nil
	}
	return options, nil
}

// DecodeOptions decodes an "sbom generate" options object into v,
// rejecting keys v has no field for.
func DecodeOptions(options json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(options))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode options: %w", err)
	}
	return nil
}

// EncodeSBOM writes bom to w as the pretty-printed CycloneDX JSON "sbom
// generate" prints.
func EncodeSBOM(w io.Writer, bom *cdx.BOM) error {
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetEscapeHTML(false)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		return fmt.Errorf("encode SBOM: %w", err)
	}
	return nil
}

// ValidateGenerated checks bom against the SBOM generation contract's
// output rules (plugins/contracts/sbom/v1/CONTRACT.md), all but
// determinism, which no single document can show: a described root,
// every component identified by its purl, nothing nested, dependencies
// that resolve, and no serial number or timestamp. It reports every
// broken rule, not just the first.
func ValidateGenerated(bom *cdx.BOM) error {
	var errs []error
	if bom.SerialNumber != "" {
		errs = append(errs, errors.New("serialNumber is set"))
	}

	check := func(where string, c cdx.Component) {
		if c.Name == "" {
			errs = append(errs, fmt.Errorf("%s has no name", where))
		}
		if c.PackageURL == "" {
			errs = append(errs, fmt.Errorf("%s has no purl", where))
		} else if _, err := packageurl.FromString(c.PackageURL); err != nil {
			errs = append(errs, fmt.Errorf("%s: purl %q: %w", where, c.PackageURL, err))
		}
		if c.BOMRef != c.PackageURL {
			errs = append(errs, fmt.Errorf("%s: bom-ref %q isn't its purl %q", where, c.BOMRef, c.PackageURL))
		}
		if c.Components != nil && len(*c.Components) > 0 {
			errs = append(errs, fmt.Errorf("%s has nested components", where))
		}
	}

	// bom-refs are unique among components; the root may share one,
	// when it describes a component that's also packaged.
	refs := map[string]bool{}
	for i, c := range componentList(bom.Components) {
		where := fmt.Sprintf("components[%d] (%s)", i, c.PackageURL)
		check(where, c)
		if refs[c.BOMRef] {
			errs = append(errs, fmt.Errorf("%s: bom-ref %q isn't unique", where, c.BOMRef))
		}
		refs[c.BOMRef] = true
	}

	if bom.Metadata == nil || bom.Metadata.Component == nil {
		errs = append(errs, errors.New("metadata.component is missing"))
	} else {
		root := *bom.Metadata.Component
		check("metadata.component", root)
		if root.Version == "" {
			errs = append(errs, errors.New("metadata.component has no version"))
		}
		refs[root.BOMRef] = true
	}
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		errs = append(errs, errors.New("metadata.timestamp is set"))
	}

	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if !refs[d.Ref] {
				errs = append(errs, fmt.Errorf("dependencies: ref %q names no bom-ref", d.Ref))
			}
			if d.Dependencies == nil {
				continue
			}
			for _, on := range *d.Dependencies {
				if !refs[on] {
					errs = append(errs, fmt.Errorf("dependencies: %q dependsOn %q, which names no bom-ref", d.Ref, on))
				}
			}
		}
	}

	return errors.Join(errs...)
}

// componentList dereferences a CycloneDX component list, nil when the
// document has none.
func componentList(cs *[]cdx.Component) []cdx.Component {
	if cs == nil {
		return nil
	}
	return *cs
}
