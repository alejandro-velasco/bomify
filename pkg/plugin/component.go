package plugin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

// ComponentPlugin is a component plugin's own logic (see
// plugins/contracts/component/v1/CONTRACT.md), for ComponentCommand to expose
// as the contract's "component pull", and "component pack" if it's also a
// ComponentPacker. Everything else the contract requires — flags, which are
// required when, the --log logger, and printing the result —
// ComponentCommand handles.
type ComponentPlugin interface {
	// Pull fetches the component req.Purl names into req.Output, or with
	// req.Check only verifies that it could (see the contract's check
	// mode).
	Pull(ctx context.Context, req PullRequest) (*Result, error)
}

// ComponentPacker is a ComponentPlugin whose kind has a registry format of
// its own, which "component pack" describes the component in. A
// ComponentPlugin that isn't one answers pack with the zero PackResult,
// leaving bomify to package the component in its default format.
type ComponentPacker interface {
	// Pack describes what a prior Pull wrote into req.Input as an OCI
	// artifact in the kind's own format, each blob that isn't already a
	// file in req.Input inline (see InlineBlob).
	Pack(ctx context.Context, req PackRequest) (*PackResult, error)
}

// PullRequest is one "component pull" invocation.
type PullRequest struct {
	Purl string
	// Output is the (existing, empty) directory to pull into; empty when
	// Check is set.
	Output string
	Check  bool
	// Logger writes to the invocation's --log file (see OpenLog).
	Logger *slog.Logger
	// Progress reports to the invocation's --progress file (see
	// OpenProgress); nil, which reports nothing, when it has none, as
	// with Check.
	Progress *Progress
}

// PackRequest is one "component pack" invocation.
type PackRequest struct {
	Purl string
	// Input is the directory a prior pull wrote into.
	Input string
	// Logger writes to the invocation's --log file (see OpenLog).
	Logger *slog.Logger
}

// ComponentHelp is the kind-specific help text ComponentCommand shows.
type ComponentHelp struct {
	// Pull is pull's short description, and Pack pack's, if the plugin is
	// a ComponentPacker.
	Pull, Pack string
}

// ComponentCommand builds the "component" command implementing the
// component plugin contract around p.
func ComponentCommand(p ComponentPlugin, help ComponentHelp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   ComponentSubcommand,
		Short: "Component plugin subcommands (pull/pack) — see plugins/contracts/component/v1/CONTRACT.md",
	}
	cmd.AddCommand(pullCommand(p, help.Pull), packCommand(p, help.Pack))
	return cmd
}

// componentFlags are the flags every component subcommand takes.
type componentFlags struct {
	purl     string
	logFile  string
	logColor bool
}

func (f *componentFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&f.logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&f.logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("log")
}

// run opens the --log logger and calls fn with it, printing fn's result.
func run[T any](cmd *cobra.Command, f *componentFlags, fn func(*slog.Logger) (T, error)) error {
	logger, closeLog, err := OpenLog(f.logFile, f.logColor)
	if err != nil {
		return err
	}
	defer closeLog()

	result, err := fn(logger)
	return print(cmd, result, err)
}

// requiredUnlessCheck fails if flag's value is empty without --check.
func requiredUnlessCheck(check bool, flag, value string) error {
	if !check && value == "" {
		return fmt.Errorf("required flag(s) %q not set", flag)
	}
	return nil
}

func pullCommand(p ComponentPlugin, short string) *cobra.Command {
	var (
		flags        componentFlags
		req          PullRequest
		progressFile string
	)
	cmd := &cobra.Command{
		Use:   "pull",
		Short: short,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return requiredUnlessCheck(req.Check, "output", req.Output)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, &flags, func(logger *slog.Logger) (*Result, error) {
				progress, closeProgress, err := OpenProgress(progressFile)
				if err != nil {
					return nil, err
				}
				defer closeProgress()

				req.Purl = flags.purl
				req.Logger = logger
				req.Progress = progress
				return p.Pull(cmd.Context(), req)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&req.Output, "output", "", "directory to save the pulled component into (required unless --check)")
	cmd.Flags().BoolVar(&req.Check, "check", false, "verify the component exists and is pullable without downloading it")
	cmd.Flags().StringVar(&progressFile, "progress", "", "file to report the pull's progress to (not passed with --check)")
	return cmd
}

func packCommand(p ComponentPlugin, short string) *cobra.Command {
	var (
		flags componentFlags
		req   PackRequest
	)
	packer, packs := p.(ComponentPacker)
	if !packs || short == "" {
		short = "Describe the pulled component in its kind's own registry format, if it has one"
	}
	cmd := &cobra.Command{
		Use:   "pack",
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, &flags, func(logger *slog.Logger) (*PackResult, error) {
				if !packs {
					return &PackResult{}, nil
				}
				req.Purl = flags.purl
				req.Logger = logger
				return packer.Pack(cmd.Context(), req)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&req.Input, "input", "", "directory a prior pull wrote the component into (required)")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}
