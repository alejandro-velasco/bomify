package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// ArtifactType is the referrer artifact type this fake signs as, and
// (unless FAKESIGN_TYPES overrides it) the only one it verifies.
const ArtifactType = "application/vnd.bomify.test.signature"

// MediaType is the media type of this fake's envelope blob.
const MediaType = "application/vnd.bomify.test.signature.v1+json"

type optionFlags []string

func (o *optionFlags) String() string     { return strings.Join(*o, ",") }
func (o *optionFlags) Set(v string) error { *o = append(*o, v); return nil }

// signatureMain implements the signing contract: "signature
// <sign|attest|verify|supported-types>". Its "signature" is an HMAC-SHA256 of
// the payload, keyed by --option key=<secret>, so verifying with any
// other key fails exactly like a real plugin rejecting an untrusted
// signer.
func signatureMain() {
	if len(os.Args) < 3 {
		fail("usage: fakeplugin signature <sign|verify|supported-types> [flags]")
	}

	switch os.Args[2] {
	case "supported-types":
		types := []string{ArtifactType}
		if env := os.Getenv("FAKESIGN_TYPES"); env != "" {
			types = strings.Split(env, ",")
		}
		print(map[string]any{"artifactTypes": types})
	case "sign":
		sign("payload", "")
	case "attest":
		sign("statement", pluginlib.InTotoPayloadType)
	case "verify":
		verify()
	default:
		fail("unknown subcommand " + os.Args[2])
	}
}

// sign implements "signature sign" (payloadFlag "payload") and
// "signature attest" (payloadFlag "statement", with payloadType set).
func sign(payloadFlag, payloadType string) {
	fs := flag.NewFlagSet(os.Args[2], flag.ExitOnError)
	payload := fs.String(payloadFlag, "", "")
	ref := fs.String("reference", "", "")
	var options optionFlags
	fs.Var(&options, "option", "")
	fs.Parse(os.Args[3:])

	if *ref == "" {
		fail("--reference is required")
	}
	key := option(options, "key")
	data := read(*payload)

	// An attestation's "envelope" records its payload type, standing in
	// for a DSSE envelope, so tests can tell it from a signature.
	envelope, _ := json.Marshal(map[string]string{"key": key, "mac": mac(key, data), "payloadType": payloadType})
	print(map[string]any{
		"artifactType": ArtifactType,
		"mediaType":    MediaType,
		"envelope":     envelope,
	})
}

func verify() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	payload := fs.String("payload", "", "")
	envelopePath := fs.String("envelope", "", "")
	mediaType := fs.String("media-type", "", "")
	ref := fs.String("reference", "", "")
	var options optionFlags
	fs.Var(&options, "option", "")
	fs.Parse(os.Args[3:])

	if *ref == "" {
		fail("--reference is required")
	}
	if *mediaType != MediaType {
		fail("unsupported envelope media type " + *mediaType)
	}
	key := option(options, "key")

	var envelope map[string]string
	if err := json.Unmarshal(read(*envelopePath), &envelope); err != nil {
		fail("malformed envelope: " + err.Error())
	}
	if !hmac.Equal([]byte(envelope["mac"]), []byte(mac(key, read(*payload)))) {
		fail("signature does not verify with the given key")
	}
	print(map[string]any{"signer": "key:" + key})
}

func option(options []string, name string) string {
	for _, o := range options {
		if k, v, ok := strings.Cut(o, "="); ok && k == name {
			return v
		}
	}
	fail("--option " + name + "=... is required")
	return ""
}

func mac(key string, data []byte) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	return data
}

func print(v any) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
