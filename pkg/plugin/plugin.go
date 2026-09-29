// Package plugin is the Go library for implementing a bomify-plugin-<kind>
// binary: the Result/Hash/RemoteResult types the component plugin
// contract's JSON output mirrors, SecurityResult for the security
// scanning contract's, SignResult/VerifyResult for the signing
// contract's, their Print methods to emit them correctly, and (in
// log.go) OpenLog for a component plugin's --log file. See
// plugins/COMPONENT-CONTRACT.md, plugins/SECURITY-CONTRACT.md, and
// plugins/SIGNING-CONTRACT.md for the contracts this package implements
// one side of; unlike those documents,
// this package is importable from outside this module, so a third-party
// plugin (in its own separate Go module) can depend on it directly.
package plugin

import (
	"encoding/json"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Result is the structured output a plugin prints to stdout on success.
type Result struct {
	// OutputPath is the location of the artifact the plugin produced.
	OutputPath string `json:"outputPath"`
	// Message is an optional human-readable summary of what happened.
	Message string `json:"message,omitempty"`
	// Hash is the content hash of the pulled artifact, for the algorithm
	// requested via --hash. A pull plugin should leave this zero if it
	// cannot compute a hash for the requested algorithm.
	Hash Hash `json:"hash,omitempty"`
}

// Hash is a content hash reported by a plugin, mirroring cdx.Hash.
type Hash struct {
	Algorithm cdx.HashAlgorithm `json:"algorithm,omitempty"`
	Value     string            `json:"value,omitempty"`
}

// Print writes r to w as the single JSON object bomify expects a plugin to
// print to stdout on success. Plugins should call this instead of
// re-implementing JSON encoding themselves.
func (r *Result) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}

// RemoteResult is the structured output a plugin prints to stdout on
// success for its "remote" subcommand.
type RemoteResult struct {
	// Remote identifies where a component's content comes from or is
	// published under — a registry/namespace address, a source URL, etc.
	// It must be in the same shape push's own --remote expects to
	// receive: without the component's own trailing name if push appends
	// that itself, or the exact complete destination if push doesn't
	// append anything at all — see plugins/COMPONENT-CONTRACT.md's RemoteResult
	// section for why. A distribution rule matched by --match can
	// substitute part of this value back into --remote for a later push,
	// preserving whatever came after the matched prefix.
	Remote string `json:"remote"`
}

// Print writes r to w as the single JSON object bomify expects a plugin's
// "remote" subcommand to print to stdout on success.
func (r *RemoteResult) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode remote result: %w", err)
	}
	return nil
}

// SecurityResult is the JSON object a plugin's "security scan"
// subcommand prints to stdout on success.
//
// Vulnerabilities lists every CycloneDX vulnerability the scanned purl
// is affected by. The plugin — not bomify — sets each one's Affects:
// for a purl scanned directly, Affects should reference that same purl
// string back; for a purl the plugin had to unpack into smaller pieces
// to scan at all (e.g. cataloging the packages inside a container
// image), Affects should instead reference the specific piece(s) —
// reported via Components below — actually affected, by their own
// BOMRef, never the purl that was scanned. bomify never sets or
// overwrites Affects itself: it writes Vulnerabilities, unmodified, into
// the scanned component's own vulnerability report (see
// plugins/SECURITY-CONTRACT.md).
//
// Components is optional: it lists the pieces a plugin had to unpack
// the scanned purl into to scan it at all (e.g. the packages found by
// cataloging a container image), each as a CycloneDX component with its
// own stable BOMRef. bomify writes them as the top-level components of
// the scanned component's vulnerability report, whose metadata component
// is the scanned component itself. A plugin that scans the purl directly, with nothing
// to unpack, leaves this nil.
//
// An empty (but non-nil) Vulnerabilities reports that nothing was
// found, exactly as meaningfully as a populated one.
type SecurityResult struct {
	Vulnerabilities []cdx.Vulnerability `json:"vulnerabilities"`
	Components      []cdx.Component     `json:"components,omitempty"`
}

// Print writes r to w as the single JSON object bomify expects a
// plugin's "security scan" subcommand to print to stdout on success.
func (r SecurityResult) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode security result: %w", err)
	}
	return nil
}

// SupportedComponentsResult is the JSON object a plugin's "security
// supported-components" subcommand prints to stdout on success: which
// component purl types and scan categories it supports. bomify calls
// this once per "bomify security scan" invocation — never per
// component — to decide which components in the SBOM are even worth
// dispatching to "security scan": a component whose purl type isn't
// listed in Types is skipped instead (see plugins/SECURITY-CONTRACT.md).
type SupportedComponentsResult struct {
	// Types lists the component purl types (e.g. "oci", "helm",
	// "generic") this plugin can scan.
	Types []string `json:"types"`
	// Scans lists the categories of scan this plugin performs (e.g.
	// "sca", "sast").
	Scans []string `json:"scans"`
}

// Print writes r to w as the single JSON object bomify expects a
// plugin's "security supported-components" subcommand to print to
// stdout on success.
func (r *SupportedComponentsResult) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode supported components result: %w", err)
	}
	return nil
}

// SignResult is the JSON object a plugin's "signature sign" subcommand
// prints to stdout on success: the signature envelope it produced over
// the payload it was given, plus what bomify needs to store that
// envelope as an OCI referrer of the signed package (see
// plugins/SIGNING-CONTRACT.md). bomify never parses Envelope itself — it
// stores it verbatim, and hands the exact same bytes back to "signature
// verify" later.
type SignResult struct {
	// ArtifactType is the OCI artifact type of the referrer manifest
	// bomify pushes to carry Envelope. A plugin should use its signing
	// ecosystem's own standard type (e.g.
	// "application/vnd.dev.sigstore.bundle.v0.3+json" or
	// "application/vnd.cncf.notary.signature"), not a bomify-specific
	// one, so that ecosystem's own tooling can discover it too.
	ArtifactType string `json:"artifactType"`
	// MediaType is the media type of the Envelope blob itself.
	MediaType string `json:"mediaType"`
	// Envelope is the signature envelope, base64-encoded (encoding/json's
	// standard encoding of a []byte).
	Envelope []byte `json:"envelope"`
	// Annotations are optional annotations bomify sets on the referrer
	// manifest, alongside its own.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Print writes r to w as the single JSON object bomify expects a
// plugin's "signature sign" subcommand to print to stdout on success.
func (r *SignResult) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode sign result: %w", err)
	}
	return nil
}

// VerifyResult is the JSON object a plugin's "signature verify"
// subcommand prints to stdout when the envelope it was given is a valid
// signature over the payload, by a signer its own trust configuration
// accepts. A plugin reports a failed verification by exiting non-zero
// instead, never by printing a VerifyResult.
type VerifyResult struct {
	// Signer is a human-readable identity of whoever produced the
	// signature (a key fingerprint, a certificate subject, an email
	// address, ...), which bomify only logs.
	Signer string `json:"signer"`
}

// Print writes r to w as the single JSON object bomify expects a
// plugin's "signature verify" subcommand to print to stdout on success.
func (r *VerifyResult) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode verify result: %w", err)
	}
	return nil
}

// SupportedSignatureTypesResult is the JSON object a plugin's "signature
// supported-types" subcommand prints to stdout on success: which
// referrer artifact types it can verify. bomify only hands a plugin's
// "signature verify" the envelopes of referrers whose artifact type is
// listed here (see plugins/SIGNING-CONTRACT.md).
type SupportedSignatureTypesResult struct {
	ArtifactTypes []string `json:"artifactTypes"`
}

// Print writes r to w as the single JSON object bomify expects a
// plugin's "signature supported-types" subcommand to print to stdout on
// success.
func (r *SupportedSignatureTypesResult) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode supported signature types result: %w", err)
	}
	return nil
}
