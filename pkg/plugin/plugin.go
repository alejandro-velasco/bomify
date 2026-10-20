// Package plugin is the Go library for implementing a bomify-plugin-<kind>
// binary: the Result/Hash/PackResult types the component plugin contract's
// JSON output mirrors, SecurityResult for the security scanning contract's,
// SignResult/VerifyResult for the signing contract's, ContractResult for the
// contract versions every plugin reports, and Print to emit any of them
// correctly. On top of those, ComponentCommand, SecurityCommand, and
// SignatureCommand build each contract's whole subcommand tree — its flags,
// validation, logging, and output — around a plugin's own implementation, and
// Run executes a plugin's root command with the contract's exit-code and
// stderr rules. See plugins/contracts/component/v1/CONTRACT.md,
// plugins/contracts/security/v1/CONTRACT.md, and
// plugins/contracts/signing/v1/CONTRACT.md for the contracts this package
// implements one side of; unlike those documents, this package is importable
// from outside this module, so a third-party plugin (in its own separate Go
// module) can depend on it directly.
package plugin

import (
	"crypto/sha256"
	"encoding/hex"
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
	// Hash is the pulled artifact's SHA-256 (see NewHash). A pull plugin
	// should leave this zero if it cannot compute one.
	Hash Hash `json:"hash,omitempty"`
}

// Hash is a content hash reported by a plugin, mirroring cdx.Hash. Its
// Algorithm is always HashAlgorithm (see NewHash).
type Hash struct {
	Algorithm cdx.HashAlgorithm `json:"algorithm,omitempty"`
	Value     string            `json:"value,omitempty"`
}

// PackResult is what a plugin's "pack" subcommand prints: the component
// as an OCI artifact in its kind's own registry format, a Manifest and
// every blob it refers to, for bomify to put in the package's index as it
// is. The zero PackResult, printed as {}, means the kind has no format of
// its own, and bomify packages the component in its default (see
// plugins/contracts/component/v1/CONTRACT.md).
type PackResult struct {
	// Manifest is the artifact's manifest, or an index of several.
	Manifest *PackedBlob `json:"manifest,omitempty"`
	// Blobs is every other blob the Manifest refers to, directly or
	// through the manifests an index names, in any order.
	Blobs []PackedBlob `json:"blobs,omitempty"`
}

// PackedBlob is one blob of a PackResult: its OCI descriptor's media type,
// digest, and size, and its bytes: either Path, a file within pack's
// --input holding exactly them, or, for a blob the plugin builds, Data,
// inline (see InlineBlob).
type PackedBlob struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Path      string `json:"path,omitempty"`
	// Data is base64 in JSON, at most MaxInlineBlobSize bytes.
	Data []byte `json:"data,omitempty"`
}

// MaxInlineBlobSize bounds a PackedBlob's Data: as large as a registry
// commonly allows a manifest, which is what a plugin builds.
const MaxInlineBlobSize = 4 << 20

// InlineBlob returns data, of mediaType, as a blob of a PackResult that
// carries its bytes inline, as a blob a plugin builds, such as a config
// or a manifest, does.
func InlineBlob(mediaType string, data []byte) PackedBlob {
	sum := sha256.Sum256(data)
	blob := PackedBlob{
		MediaType: mediaType,
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Size:      int64(len(data)),
		Data:      data,
	}
	return blob
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
// plugins/contracts/security/v1/CONTRACT.md).
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
//
// Unscanned, if set, says why the plugin couldn't analyze the component
// at all — e.g. nothing in the files it was given that it recognizes —
// so bomify counts it as not scanned rather than as clean. Its
// Vulnerabilities and Components are then ignored.
type SecurityResult struct {
	Vulnerabilities []cdx.Vulnerability `json:"vulnerabilities"`
	Components      []cdx.Component     `json:"components,omitempty"`
	Unscanned       string              `json:"unscanned,omitempty"`
}

// SupportedComponentsResult is the JSON object a plugin's "security
// supported-components" subcommand prints to stdout on success: which
// component purl types and scan categories it supports. bomify calls this
// once per "bomify security scan" invocation — never per component — to
// decide which components in the SBOM are even worth dispatching to "security
// scan": a component whose purl type isn't listed in Types is skipped instead
// (see plugins/contracts/security/v1/CONTRACT.md).
type SupportedComponentsResult struct {
	// Types maps each component purl type this plugin can scan (e.g.
	// "oci", "npm", "generic") to how it scans it (see ScanMode).
	Types map[string]ScanMode `json:"types"`
	// Scans lists the categories of scan this plugin performs (e.g.
	// "sca", "sast").
	Scans []string `json:"scans"`
}

// ScanMode is how a security scanning plugin scans a component of a purl
// type it supports (see SupportedComponentsResult.Types).
type ScanMode string

const (
	// ScanByPurl scans a component from its purl alone: a lookup in an
	// ecosystem, or, for an image, pulling it. bomify never passes
	// "security scan --input".
	ScanByPurl ScanMode = "purl"
	// ScanByFiles scans a component only from its pulled files, which
	// bomify passes as "security scan --input". bomify skips one whose
	// files it doesn't have, such as on a scan on pull.
	ScanByFiles ScanMode = "files"
)

// SignResult is the JSON object a plugin's "signature sign" subcommand prints
// to stdout on success: the signature envelope it produced over the payload
// it was given, plus what bomify needs to store that envelope as an OCI
// referrer of the signed package (see
// plugins/contracts/signing/v1/CONTRACT.md). bomify never parses Envelope
// itself — it stores it verbatim, and hands the exact same bytes back to
// "signature verify" later.
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

// VerifyAttestationResult is the JSON object a plugin's "signature
// verify-attestation" subcommand prints to stdout when the envelope it
// was given is a valid attestation by a signer its own trust
// configuration accepts. As for VerifyResult, a failed verification is
// reported by exiting non-zero instead.
type VerifyAttestationResult struct {
	// Signer is a human-readable identity of whoever signed the
	// attestation, which bomify only logs.
	Signer string `json:"signer"`
	// Statement is the in-toto statement the envelope signs, exactly as
	// signed, base64-encoded (encoding/json's standard encoding of a
	// []byte). bomify checks it is what it expects.
	Statement []byte `json:"statement"`
}

// SupportedSignatureTypesResult is the JSON object a plugin's "signature
// supported-types" subcommand prints to stdout on success: which
// referrer artifact types it can verify. bomify only hands a plugin's
// "signature verify" the envelopes of referrers whose artifact type is
// listed here (see plugins/contracts/signing/v1/CONTRACT.md).
type SupportedSignatureTypesResult struct {
	ArtifactTypes []string `json:"artifactTypes"`
}

// ContractResult is the JSON object every plugin's "contract" subcommand
// prints to stdout: the plugin contracts it implements (see
// plugins/README.md#contract-versions).
type ContractResult struct {
	// Contracts maps each contract the plugin implements ("component",
	// "sbom", "security", or "signing") to the major version it speaks.
	Contracts map[string]int `json:"contracts"`
}

// HashAlgorithm is the one algorithm a Result's Hash is reported in.
const HashAlgorithm = cdx.HashAlgoSHA256

// NewHash returns hex — a hex-encoded SHA-256 digest — as a Hash.
func NewHash(hex string) Hash {
	return Hash{Algorithm: HashAlgorithm, Value: hex}
}

// Print writes v — any of this package's result types — to w as the
// single JSON object bomify expects a plugin to print to stdout on
// success. HTML escaping is disabled, so purl query strings stay intact.
func Print(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}
