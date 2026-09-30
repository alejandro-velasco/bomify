package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/namedstore"
	"github.com/alejandro-velasco/bomify/internal/table"
)

// commandHelp is one command's help text.
type commandHelp struct {
	short, long, example string
}

// storeCommand describes the add/list/remove command group of one managed
// named store (see internal/namedstore): "bomify trust key" and "bomify
// security vex".
type storeCommand struct {
	// use and short are the group command's own.
	use, short string
	// path is the group's full command path, e.g. "trust key", prefixing
	// its errors.
	path string
	// noun names what's stored, e.g. "key", for log lines.
	noun string

	add    func(dataDir, name, file string) (namedstore.Entry, error)
	list   func(dataDir string) ([]namedstore.Entry, error)
	remove func(dataDir, name string) error

	addHelp, listHelp, removeHelp commandHelp
}

func (s storeCommand) command() *cobra.Command {
	cmd := &cobra.Command{Use: s.use, Short: s.short}

	cmd.AddCommand(&cobra.Command{
		Use:     "add <name> <file>",
		Short:   s.addHelp.short,
		Long:    s.addHelp.long,
		Example: s.addHelp.example,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, err := s.add(dataDir, args[0], args[1])
			if err != nil {
				return fmt.Errorf("%s add: %w", s.path, err)
			}
			logging.FromContext(cmd.Context()).Info(s.noun+" stored", "name", entry.Name, "sha256", entry.SHA256, "source", entry.Source)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:     "list",
		Short:   s.listHelp.short,
		Long:    s.listHelp.long,
		Example: s.listHelp.example,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := s.list(dataDir)
			if err != nil {
				return err
			}
			rows := make([][]string, 0, len(entries))
			for _, e := range entries {
				rows = append(rows, []string{e.Name, e.SHA256[:12], e.Added, e.Source})
			}
			return table.Write(cmd.OutOrStdout(), []string{"NAME", "SHA256", "ADDED", "SOURCE"}, rows)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:     "remove <name>",
		Short:   s.removeHelp.short,
		Long:    s.removeHelp.long,
		Example: s.removeHelp.example,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := s.remove(dataDir, args[0]); err != nil {
				return fmt.Errorf("%s remove: %w", s.path, err)
			}
			return nil
		},
	})

	return cmd
}
