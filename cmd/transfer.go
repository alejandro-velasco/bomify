package cmd

import (
	"context"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/signature"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// transferFlags are the flags every command moving whole packages shares:
// --concurrency and, where the command has one, --quiet.
type transferFlags struct {
	concurrency int
	quiet       bool
}

// register adds --concurrency (for layers being verb-ed) and, unless
// quietUsage is empty, --quiet.
func (f *transferFlags) register(cmd *cobra.Command, verb, quietUsage string) {
	cmd.Flags().IntVarP(&f.concurrency, "concurrency", "c", 3, "number of layers to "+verb+" concurrently")
	if quietUsage != "" {
		cmd.Flags().BoolVarP(&f.quiet, "quiet", "q", false, quietUsage)
	}
}

// logger returns cmd's logger, reduced to warnings and errors by --quiet.
func (f *transferFlags) logger(cmd *cobra.Command) *slog.Logger {
	logger := logging.FromContext(cmd.Context())
	if f.quiet {
		return logging.WarningsOnly(logger)
	}
	return logger
}

// transferOptions returns the transfer.Options f describes, rendering
// progress bars on stderr unless --quiet. Call done once the transfer
// ends, failed or not: it settles the bars (see startBars).
func (f *transferFlags) transferOptions(cmd *cobra.Command) (opts transfer.Options, done func()) {
	opts.Concurrency = f.concurrency
	if f.quiet {
		return opts, func() {}
	}
	bars, settle := startBars(cmd.ErrOrStderr())
	opts.Progress = newProgressFunc(bars)
	return opts, settle
}

// printPinned prints ref's pinned reference, <repository>@<digest>, on
// stdout with --quiet: the one thing --quiet output is for.
func (f *transferFlags) printPinned(cmd *cobra.Command, ref, digest string) {
	if f.quiet {
		repository := prefix.Repository(ref)
		fmt.Fprintln(cmd.OutOrStdout(), prefix.Pinned(repository, digest))
	}
}

// restoreFlags are the flags pull and load share: transferFlags, plus
// verifying and scanning each package before its tag is recorded.
type restoreFlags struct {
	transferFlags
	verify verifyFlags
	scan   scanFlags
}

func (f *restoreFlags) register(cmd *cobra.Command, verb, quietUsage string) {
	f.transferFlags.register(cmd, verb, quietUsage)
	f.verify.register(cmd)
	f.scan.register(cmd)
}

// restore is one pull or load in progress (see restoreFlags.start).
type restore struct {
	logger *slog.Logger
	opts   transfer.Options
	scan   *pullScanHook
	done   func()
}

// start validates f and resolves the transfer.Options a pull or load
// runs with: signature and provenance verification, then a fresh scan
// and gate. Call
// finish once the transfer succeeds.
func (f *restoreFlags) start(cmd *cobra.Command) (*restore, error) {
	logger := f.logger(cmd)

	policy, err := f.verify.policy(dataDir)
	if err != nil {
		return nil, err
	}
	if err := f.scan.validate(); err != nil {
		return nil, err
	}
	verifier := signature.NewVerifier(layout.Plugins(dataDir), policy, logger)
	scan := &pullScanHook{flags: &f.scan, w: cmd.ErrOrStderr(), concurrency: f.concurrency, logger: logger, policy: policy, verify: verifier}

	opts, done := f.transferOptions(cmd)
	opts.Verify, opts.Scan = verifier, scan.scan
	opts.VerifyProvenance = signature.NewProvenanceVerifier(layout.Plugins(dataDir), policy, logger)
	return &restore{logger: logger, opts: opts, scan: scan, done: done}, nil
}

// finish settles progress output and keeps the fresh scan's reports,
// written after the packages' own so they replace what the publisher
// attached. Call it only once the transfer has succeeded.
func (r *restore) finish() error {
	r.done()
	return writeReports(r.scan.collected)
}

// publishFlags are the flags push and save share: transferFlags, plus
// signing each package as it's packed and the VEX documents to attach to
// it.
type publishFlags struct {
	transferFlags
	sign signFlags
	vex  []string
}

func (f *publishFlags) register(cmd *cobra.Command, verb, quietUsage string) {
	f.transferFlags.register(cmd, verb, quietUsage)
	f.sign.register(cmd)
	cmd.Flags().StringArrayVar(&f.vex, "vex", nil, "attach this VEX document to the package: a name from \"bomify security vex add\", or a file (repeatable)")
}

// transferOptions is transferFlags.transferOptions plus a signer and
// attester signing with --sign and every --signer, and the VEX documents
// --vex names, each attached to the package.
func (f *publishFlags) transferOptions(cmd *cobra.Command, logger *slog.Logger) (transfer.Options, func(), error) {
	plugins, err := f.sign.plugins(dataDir)
	if err != nil {
		return transfer.Options{}, nil, err
	}
	var (
		signer   transfer.Signer
		attester transfer.Attester
	)
	signs := len(plugins) > 0
	if signs {
		if signer, attester, err = signature.NewSigners(layout.Plugins(dataDir), plugins, logger); err != nil {
			return transfer.Options{}, nil, err
		}
	}
	if len(f.vex) > 0 && !signs {
		logger.Warn("attaching VEX without --sign or --signer: pulls only apply a package's VEX when they verify its signature, so this VEX will be ignored", "documents", len(f.vex))
	}
	var attach []transfer.Attachment
	for _, arg := range f.vex {
		doc, err := security.ReadVEX(dataDir, arg)
		if err != nil {
			return transfer.Options{}, nil, fmt.Errorf("--vex %s: %w", arg, err)
		}
		attach = append(attach, doc.Attachment())
	}

	opts, done := f.transferFlags.transferOptions(cmd)
	opts.Sign, opts.Attest, opts.Attach = signer, attester, attach
	opts.Pack = packComponent(logger)
	return opts, done, nil
}

// packComponent returns a transfer.Packer packing each component with its
// plugin's "component pack" (see plugin.Pack). A plugin binary, which has
// no plugin of its own, is packaged in bomify's own format.
func packComponent(logger *slog.Logger) transfer.Packer {
	return func(ctx context.Context, component cdx.Component, dir string) (*pluginlib.PackResult, error) {
		_, isBinary, err := plugin.ParseBinary(component)
		if err != nil {
			return nil, err
		}
		if isBinary {
			return &pluginlib.PackResult{}, nil
		}
		_, path, err := resolvePlugin(component, logger)
		if err != nil {
			return nil, err
		}
		return plugin.Pack(path, component, dataDir, dir, logger)
	}
}
