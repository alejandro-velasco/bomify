package plugin

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

// ComponentPlugin is a component plugin's own logic (see
// plugins/COMPONENT-CONTRACT.md), for ComponentCommand to expose as the
// contract's "component pull"/"component push"/"component remote".
// Everything else the contract requires — flags, which are required
// when, the --log logger, and printing the result — ComponentCommand
// handles.
type ComponentPlugin interface {
	// Pull fetches the component req.Purl names into req.Output, or with
	// req.Check only verifies that it could (see the contract's check
	// mode).
	Pull(ctx context.Context, req PullRequest) (*Result, error)
	// Push publishes what a prior Pull wrote into req.Input to req.Remote,
	// or with req.Check only verifies that it could.
	Push(ctx context.Context, req PushRequest) (*Result, error)
	// Remote reports where the component purl names comes from or is
	// published under (see RemoteResult). It must be a pure function of
	// purl.
	Remote(ctx context.Context, purl string, logger *slog.Logger) (string, error)
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
}

// PushRequest is one "component push" invocation.
type PushRequest struct {
	Purl string
	// Input is the directory a prior pull wrote into; empty when Check is
	// set.
	Input  string
	Remote string
	Check  bool
	// Logger writes to the invocation's --log file (see OpenLog).
	Logger *slog.Logger
}

// ComponentHelp is the kind-specific help text ComponentCommand shows.
type ComponentHelp struct {
	// Pull, Push, and Remote are each subcommand's short description.
	Pull, Push, Remote string
	// RemoteFlag describes the shape push's --remote takes, which is
	// entirely up to the plugin.
	RemoteFlag string
}

// ComponentCommand builds the "component" command implementing the
// component plugin contract around p.
func ComponentCommand(p ComponentPlugin, help ComponentHelp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component",
		Short: "Component plugin subcommands (pull/push/remote) — see plugins/COMPONENT-CONTRACT.md",
	}
	cmd.AddCommand(pullCommand(p, help.Pull), pushCommand(p, help.Push, help.RemoteFlag), remoteCommand(p, help.Remote))
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
		flags componentFlags
		req   PullRequest
	)
	cmd := &cobra.Command{
		Use:   "pull",
		Short: short,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return requiredUnlessCheck(req.Check, "output", req.Output)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, &flags, func(logger *slog.Logger) (*Result, error) {
				req.Purl, req.Logger = flags.purl, logger
				return p.Pull(cmd.Context(), req)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&req.Output, "output", "", "directory to save the pulled component into (required unless --check)")
	cmd.Flags().BoolVar(&req.Check, "check", false, "verify the component exists and is pullable without downloading it")
	return cmd
}

func pushCommand(p ComponentPlugin, short, remoteUsage string) *cobra.Command {
	var (
		flags componentFlags
		req   PushRequest
	)
	cmd := &cobra.Command{
		Use:   "push",
		Short: short,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return requiredUnlessCheck(req.Check, "input", req.Input)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, &flags, func(logger *slog.Logger) (*Result, error) {
				req.Purl, req.Logger = flags.purl, logger
				return p.Push(cmd.Context(), req)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&req.Input, "input", "", "directory a prior pull wrote the component into (required unless --check)")
	cmd.Flags().StringVar(&req.Remote, "remote", "", remoteUsage+" (required)")
	cmd.Flags().BoolVar(&req.Check, "check", false, "verify pushing to remote would succeed, without publishing anything")
	_ = cmd.MarkFlagRequired("remote")
	return cmd
}

func remoteCommand(p ComponentPlugin, short string) *cobra.Command {
	var flags componentFlags
	cmd := &cobra.Command{
		Use:   "remote",
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, &flags, func(logger *slog.Logger) (*RemoteResult, error) {
				remote, err := p.Remote(cmd.Context(), flags.purl, logger)
				return &RemoteResult{Remote: remote}, err
			})
		},
	}
	flags.register(cmd)
	return cmd
}
