package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/alejandro-velasco/bomify/internal/auth"
)

type loginOptions struct {
	username      string
	password      string
	passwordStdin bool
}

func loginCmd() *cobra.Command {
	opts := &loginOptions{}

	cmd := &cobra.Command{
		Use:   "login [server]",
		Short: "Log in to an OCI registry",
		Long:  "Login authenticates against an OCI registry (default: docker.io) and stores the credentials for later build/distribute/pull/push operations to reuse — using the same credential store `docker login` itself reads and writes, so credentials from either tool work for both.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := auth.DefaultHost
			if len(args) == 1 {
				host = args[0]
			}
			if err := runLogin(cmd, host, opts); err != nil {
				return fmt.Errorf("login: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.username, "username", "u", "", "username")
	cmd.Flags().StringVarP(&opts.password, "password", "p", "", "password (insecure: prefer --password-stdin, or the interactive prompt)")
	cmd.Flags().BoolVar(&opts.passwordStdin, "password-stdin", false, "read the password from stdin")

	return cmd
}

func runLogin(cmd *cobra.Command, host string, opts *loginOptions) error {
	username := opts.username
	password := opts.password

	if opts.passwordStdin {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		// Windows' cmd.exe and PowerShell both append a CRLF to the end of piped input,
		// so trim any trailing whitespace here.
		password = strings.TrimRight(string(data), "\r\n")
	}

	if username == "" {
		var err error
		username, err = promptLine(cmd, "Username: ")
		if err != nil {
			return err
		}
	}

	if password == "" {
		var err error
		password, err = promptPassword(cmd, "Password: ")
		if err != nil {
			return err
		}
	}

	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}

	result, err := auth.Login(cmd.Context(), host, username, password)
	if err != nil {
		return err
	}

	if result.PlaintextFallback {
		fmt.Fprintln(cmd.ErrOrStderr(), "WARNING! Your credentials are stored unencrypted in your config file.")
		fmt.Fprintln(cmd.ErrOrStderr(), "Configure a credential helper to remove this warning. See")
		fmt.Fprintln(cmd.ErrOrStderr(), "https://docs.docker.com/engine/reference/commandline/login/#credentials-store")
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Login Succeeded")
	return nil
}

func promptLine(cmd *cobra.Command, label string) (string, error) {
	fmt.Fprint(cmd.OutOrStdout(), label)

	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// promptPassword prompts for and reads a password, masking input when
// stdin is a real interactive terminal, and falling back to a plain line
// read otherwise (e.g. input piped in from a script or test).
func promptPassword(cmd *cobra.Command, label string) (string, error) {
	fmt.Fprint(cmd.OutOrStdout(), label)

	if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		data, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(cmd.OutOrStdout())
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(data), nil
	}

	return promptLine(cmd, "")
}
