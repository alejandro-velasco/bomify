package cmd

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/table"
)

const packagesShort = "List built packages"

const packagesLong = `Packages lists local packages, one row per repository:tag. SIZE is the
on-disk size of the package's components (0 for any not pulled).`

const packagesExample = `  # List every locally recorded package
  bomify packages`

type packagesOptions struct{}

func packagesCmd() *cobra.Command {
	opts := &packagesOptions{}

	cmd := &cobra.Command{
		Use:     "packages",
		Short:   packagesShort,
		Long:    packagesLong,
		Example: packagesExample,
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
	Size       int64
}

func runPackages(cmd *cobra.Command, opts *packagesOptions) error {
	repos, err := build.ReadRepositories(dataDir)
	if err != nil {
		return err
	}

	// Cache by sbom hash, not per row: the same build is often reachable
	// under several tags, and PackageSize walks every component's layer
	// directory on disk — not something worth redoing per tag.
	sizes := map[string]int64{}

	var rows []packageRow
	for repo, tags := range repos {
		for tag, id := range tags {
			size, ok := sizes[id]
			if !ok {
				size = packageSize(dataDir, id)
				sizes[id] = size
			}

			rows = append(rows, packageRow{
				Repository: repo,
				Tag:        tag,
				ID:         id,
				Created:    manifestCreated(dataDir, id),
				Size:       size,
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

	header := []string{"REPOSITORY", "TAG", "PACKAGE ID", "CREATED", "SIZE"}
	cells := make([][]string, 0, len(rows))
	for _, row := range rows {
		cells = append(cells, []string{row.Repository, row.Tag, shortID(row.ID), humanAge(row.Created), fmt.Sprintf("%.1f", decor.SizeB1024(row.Size))})
	}
	table.RightAlign(4, header, cells)
	return table.Write(cmd.OutOrStdout(), header, cells)
}

// packageSize returns the total on-disk size of sbomHash's components
// (see build.PackageSize), or 0 if it can't be computed — e.g. a
// missing or corrupt manifest — rather than failing the whole listing
// over one bad row, mirroring manifestCreated's same degrade-not-fail
// behavior.
func packageSize(baseDir, sbomHash string) int64 {
	size, err := build.PackageSize(baseDir, sbomHash)
	if err != nil {
		return 0
	}
	return size
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
	info, err := os.Stat(layout.Manifest(baseDir, sbomHash))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// humanAge renders t as a rough, human-friendly age, or "-" if t is unknown.
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
