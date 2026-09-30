package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/signature"
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
// ends, so the bars settle before anything else is written.
func (f *transferFlags) transferOptions(cmd *cobra.Command) (opts transfer.Options, done func()) {
	opts.Concurrency = f.concurrency
	if f.quiet {
		return opts, func() {}
	}
	mb := newMultiBar(cmd.ErrOrStderr())
	opts.Progress = newProgressFunc(mb)
	return opts, mb.Wait
}

// printPinned prints ref's pinned reference, <repository>@<digest>, on
// stdout with --quiet: the one thing --quiet output is for.
func (f *transferFlags) printPinned(cmd *cobra.Command, ref, digest string) {
	if f.quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "%s@%s\n", prefix.Repository(ref), digest)
	}
}

// restoreFlags are the flags pull and load share: transferFlags, plus
// verifying and scanning each package before any of it is restored.
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
// runs with: signature verification, then a fresh scan and gate. Call
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

// transferOptions is transferFlags.transferOptions plus the signer and
// attester --sign describes and the VEX documents --vex names, each
// attached to the package.
func (f *publishFlags) transferOptions(cmd *cobra.Command, logger *slog.Logger) (transfer.Options, func(), error) {
	signer, attester, err := f.sign.signers(logger)
	if err != nil {
		return transfer.Options{}, nil, err
	}
	if len(f.vex) > 0 && signer == nil {
		logger.Warn("attaching VEX without --sign: pulls only apply a package's VEX when they verify its signature, so this VEX will be ignored", "documents", len(f.vex))
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
	return opts, done, nil
}
