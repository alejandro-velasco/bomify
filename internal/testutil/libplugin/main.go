// Command libplugin is a bomify-plugin-* binary built with pkg/plugin's
// command builders, used only by tests to check that the arguments bomify
// passes a plugin parse against them: unlike fakeplugin, which hand-rolls
// each contract as written, here bomify's calls meet the flags and
// validation every Go plugin gets. Each contract is implemented
// trivially, answering from its request so tests can check what arrived.
// Install it with testutil.InstallLibPlugin.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

func main() {
	plugin.Run(plugin.NewRootCommand("lib", "bomify plugin built with pkg/plugin, for tests",
		plugin.ComponentCommand(component{}, plugin.ComponentHelp{}),
		plugin.SecurityCommand(scanner{}, plugin.SecurityHelp{}),
		plugin.SignatureCommand(signer{}, plugin.SigningHelp{}),
		plugin.SBOMCommand(generator{}, plugin.SBOMHelp{})))
}

// generator takes one option, "name", and describes a pkg:generic
// component of that name, as both root and its one component.
type generator struct{}

func (generator) Generate(_ context.Context, options json.RawMessage, _ *slog.Logger) (*cdx.BOM, error) {
	var o struct {
		Name string `json:"name"`
	}
	if err := plugin.DecodeOptions(options, &o); err != nil {
		return nil, err
	}
	purl := "pkg:generic/" + o.Name + "@1.0"
	root := cdx.Component{Name: o.Name, Version: "1.0", PackageURL: purl, BOMRef: purl}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &root}
	bom.Components = &[]cdx.Component{root}
	return bom, nil
}

// component pulls a one-file artifact named after the purl's last path
// segment, pushes nowhere, and reports "remote-of-<purl>" as the remote.
type component struct{}

func (component) Pull(_ context.Context, req plugin.PullRequest) (*plugin.Result, error) {
	if req.Check {
		return &plugin.Result{OutputPath: req.Purl}, nil
	}
	out := filepath.Join(req.Output, "artifact")
	if err := os.WriteFile(out, []byte(req.Purl), 0o644); err != nil {
		return nil, err
	}
	return &plugin.Result{OutputPath: out}, nil
}

func (component) Push(_ context.Context, req plugin.PushRequest) (*plugin.Result, error) {
	return &plugin.Result{OutputPath: req.Remote}, nil
}

func (component) Remote(_ context.Context, purl string, _ *slog.Logger) (string, error) {
	return "remote-of-" + purl, nil
}

// scanner finds nothing, and supports oci components, and generic ones
// given their files. Scanning those, it reports it couldn't analyze them,
// naming the files it was given.
type scanner struct{}

func (scanner) Scan(context.Context, string) (plugin.SecurityResult, error) {
	return plugin.SecurityResult{Vulnerabilities: []cdx.Vulnerability{}}, nil
}

func (scanner) ScanInput(_ context.Context, _, input string) (plugin.SecurityResult, error) {
	return plugin.SecurityResult{Unscanned: "nothing to analyze in " + input}, nil
}

func (scanner) SupportedComponents(context.Context) (plugin.SupportedComponentsResult, error) {
	return plugin.SupportedComponentsResult{
		Types: map[string]plugin.ScanMode{"oci": plugin.ScanByPurl, "generic": plugin.ScanByFiles},
		Scans: []string{"sca"},
	}, nil
}

// signer's envelope is what it signed, and it reports the reference it
// was given as the signer.
type signer struct{}

// artifactType is the one artifact type signer produces and verifies.
const artifactType = "application/vnd.bomify.test.libplugin"

func (signer) Sign(_ context.Context, req plugin.SignRequest) (plugin.SignResult, error) {
	return plugin.SignResult{ArtifactType: artifactType, MediaType: artifactType, Envelope: req.Payload}, nil
}

func (signer) Attest(_ context.Context, req plugin.AttestRequest) (plugin.SignResult, error) {
	return plugin.SignResult{ArtifactType: artifactType, MediaType: artifactType, Envelope: req.Statement}, nil
}

func (signer) Verify(_ context.Context, req plugin.VerifyRequest) (plugin.VerifyResult, error) {
	return plugin.VerifyResult{Signer: req.Reference}, nil
}

func (signer) VerifyAttestation(_ context.Context, req plugin.VerifyAttestationRequest) (plugin.VerifyAttestationResult, error) {
	return plugin.VerifyAttestationResult{Signer: req.Reference, Statement: req.Envelope}, nil
}

func (signer) SupportedTypes(context.Context) (plugin.SupportedSignatureTypesResult, error) {
	return plugin.SupportedSignatureTypesResult{ArtifactTypes: []string{artifactType}}, nil
}
