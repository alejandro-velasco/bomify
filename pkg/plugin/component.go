package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"
)

// ComponentPlugin is a component plugin's own logic (see
// plugins/contracts/component/v1/CONTRACT.md), for ComponentCommand to expose
// as the contract's "component pull"/"component push"/"component remote",
// and "component pack" if it's also a ComponentPacker. Everything else the
// contract requires — flags, which are required when, the --log logger, and
// printing the result — ComponentCommand handles.
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

// ComponentPacker is a ComponentPlugin whose kind has a registry format of
// its own, which "component pack" describes the component in. A
// ComponentPlugin that isn't one answers pack with the zero PackResult,
// leaving bomify to publish its default.
type ComponentPacker interface {
	// Pack describes what a prior Pull wrote into req.Input as an OCI
	// artifact in the kind's own format, writing any blob that isn't
	// already a file in req.Input into req.Output.
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

// PackRequest is one "component pack" invocation.
type PackRequest struct {
	Purl string
	// Input is the directory a prior pull wrote into, and Output an
	// (existing, empty) directory for any blob that isn't a file there.
	Input  string
	Output string
	// Annotations are bomify's, to add to the manifest Pack builds, or to
	// leave out of one it publishes unchanged.
	Annotations map[string]string
	// Logger writes to the invocation's --log file (see OpenLog).
	Logger *slog.Logger
}

// ComponentHelp is the kind-specific help text ComponentCommand shows.
type ComponentHelp struct {
	// Pull, Push, and Remote are each subcommand's short description.
	// Pack's, if the plugin is a ComponentPacker, is Pack's.
	Pull, Push, Remote, Pack string
	// RemoteFlag describes the shape push's --remote takes, which is
	// entirely up to the plugin.
	RemoteFlag string
}

// ComponentCommand builds the "component" command implementing the
// component plugin contract around p.
func ComponentCommand(p ComponentPlugin, help ComponentHelp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   ComponentSubcommand,
		Short: "Component plugin subcommands (pull/push/remote/pack) — see plugins/contracts/component/v1/CONTRACT.md",
	}
	cmd.AddCommand(pullCommand(p, help.Pull), pushCommand(p, help.Push, help.RemoteFlag), remoteCommand(p, help.Remote), packCommand(p, help.Pack))
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

func packCommand(p ComponentPlugin, short string) *cobra.Command {
	var (
		flags           componentFlags
		req             PackRequest
		annotationFlags []string
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
				annotations, err := parseAnnotations(annotationFlags)
				if err != nil {
					return nil, err
				}
				req.Purl, req.Annotations, req.Logger = flags.purl, annotations, logger
				return packer.Pack(cmd.Context(), req)
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&req.Input, "input", "", "directory a prior pull wrote the component into (required)")
	cmd.Flags().StringVar(&req.Output, "output", "", "directory to write any new blob into (required)")
	cmd.Flags().StringArrayVar(&annotationFlags, "annotation", nil, "annotation, as key=value, to add to the manifest built (repeatable)")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

// parseAnnotations parses pack's --annotation values, each key=value.
func parseAnnotations(values []string) (map[string]string, error) {
	annotations := make(map[string]string, len(values))
	for _, value := range values {
		key, annotation, ok := strings.Cut(value, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("--annotation %q isn't key=value", value)
		}
		annotations[key] = annotation
	}
	return annotations, nil
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
