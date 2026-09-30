package security

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/namedstore"
)

// StoredVEX is one VEX document in a data directory's managed store (see
// AddVEX): an immutable copy of the file it was added from, named so
// scan policy rules can refer to it (see Rule.VEX).
type StoredVEX = namedstore.Entry

func vexStore(baseDir string) namedstore.Store {
	return namedstore.Store{Dir: layout.VEX(baseDir), Ext: ".vex", Kind: "VEX document"}
}

// VEXPath returns the path of the stored VEX document whose content
// hashes to sha256.
func VEXPath(baseDir, sha256 string) string {
	return vexStore(baseDir).Path(sha256)
}

// ListVEX returns every document in baseDir's managed VEX store, sorted
// by name.
func ListVEX(baseDir string) ([]StoredVEX, error) {
	return vexStore(baseDir).List()
}

// AddVEX copies the VEX document at path into baseDir's managed store
// under name — after checking it loads (see LoadVEX) — replacing
// whatever name referred to before. The copy is content-addressed, so
// later edits to path don't reach the store until it's added again, and
// a scan decision can always be traced to the exact document behind it.
func AddVEX(baseDir, name, path string) (StoredVEX, error) {
	store := vexStore(baseDir)
	if err := namedstore.ValidateName(store.Kind, name); err != nil {
		return StoredVEX{}, err
	}
	if _, err := LoadVEX([]string{path}); err != nil {
		return StoredVEX{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return StoredVEX{}, fmt.Errorf("read %s: %w", path, err)
	}
	return store.Add(name, path, data)
}

// RemoveVEX removes name from baseDir's managed VEX store, deleting its
// stored copy unless another name still refers to the same content. It
// refuses while a scan policy rule refers to name, so no rule is left
// pointing at nothing.
func RemoveVEX(baseDir, name string) error {
	rules, err := ReadConfig(baseDir)
	if err != nil {
		return err
	}
	var users []string
	for _, rule := range rules {
		if slices.Contains(rule.VEX, name) {
			users = append(users, fmt.Sprintf("%q", wildcardMatch(rule.Match)))
		}
	}
	if len(users) > 0 {
		return fmt.Errorf("VEX document %q is still used by scan policy rule(s) %s; remove it from them first", name, strings.Join(users, ", "))
	}
	return vexStore(baseDir).Remove(name)
}

// ResolveVEX returns the stored copy's path for each of names, in order,
// failing on any name not in baseDir's managed store.
func ResolveVEX(baseDir string, names []string) ([]string, error) {
	paths, err := vexStore(baseDir).Resolve(names)
	if err != nil {
		return nil, fmt.Errorf("%w (see \"bomify security vex add\")", err)
	}
	return paths, nil
}

// wildcardMatch renders a rule's Match as "bomify security policy list"
// does: "*" for one that applies to every package.
func wildcardMatch(match string) string {
	if match == "" {
		return "*"
	}
	return match
}
