package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
)

type packagesOptions struct{}

func packagesCmd() *cobra.Command {
	opts := &packagesOptions{}

	cmd := &cobra.Command{
		Use:   "packages",
		Short: "List built packages",
		Long:  "Packages lists the packages recorded in <output>/package/repositories.json, one row per repository:tag, similar to `docker images`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPackages(cmd, opts)
		},
	}

	return cmd
}

// packageRow is one repository:tag entry, ready to print.
type packageRow struct {
	Repository string
	Tag        string
	ID         string
	Created    time.Time
}

func runPackages(cmd *cobra.Command, opts *packagesOptions) error {
	repos, err := build.ReadRepositories(dataDir)
	if err != nil {
		return err
	}

	var rows []packageRow
	for repo, tags := range repos {
		for tag, id := range tags {
			rows = append(rows, packageRow{
				Repository: repo,
				Tag:        tag,
				ID:         id,
				Created:    manifestCreated(dataDir, id),
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Repository != rows[j].Repository {
			return rows[i].Repository < rows[j].Repository
		}
		if rows[i].Tag != rows[j].Tag {
			return rows[i].Tag < rows[j].Tag
		}
		return rows[i].Created.After(rows[j].Created)
	})

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "REPOSITORY\tTAG\tPACKAGE ID\tCREATED")
	for _, row := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.Repository, row.Tag, shortID(row.ID), humanAge(row.Created))
	}

	return w.Flush()
}

// shortID mirrors truncated image IDs: the first 12
// characters of the full hash.
func shortID(id string) string {
	const shortLen = 12
	if len(id) <= shortLen {
		return id
	}
	return id[:shortLen]
}

// manifestCreated returns the modification time of the manifest for
// sbomHash, or the zero time if it can't be read (e.g. the manifest is
// missing, which repositories.json alone doesn't guard against).
func manifestCreated(baseDir, sbomHash string) time.Time {
	info, err := os.Stat(build.ManifestPath(baseDir, sbomHash))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// humanAge renders t the way `docker images` renders CREATED: a rough,
// human-friendly age, or "-" if t is unknown.
func humanAge(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "Less than a minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%d months ago", int(d.Hours()/24/30))
	default:
		return fmt.Sprintf("%d years ago", int(d.Hours()/24/365))
	}
}
