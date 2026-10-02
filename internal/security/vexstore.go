package security

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/namedstore"
	"github.com/alejandro-velasco/bomify/internal/rules"
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
	doc, err := readVEX(path, path)
	if err != nil {
		return StoredVEX{}, err
	}
	return store.Add(name, path, doc.Data)
}

// ReadVEX returns the VEX document arg names: the one stored in
// baseDir's managed store under that name, if any, or else the file at
// arg — checked to load, either way.
func ReadVEX(baseDir, arg string) (VEXDocument, error) {
	stored, err := ListVEX(baseDir)
	if err != nil {
		return VEXDocument{}, err
	}
	if i := slices.IndexFunc(stored, func(e StoredVEX) bool { return e.Name == arg }); i >= 0 {
		return readVEX(arg, VEXPath(baseDir, stored[i].SHA256))
	}
	if _, err := os.Stat(arg); err != nil {
		return VEXDocument{}, fmt.Errorf("%q is neither a stored VEX document (see \"bomify security vex list\") nor a file: %w", arg, err)
	}
	return readVEX(filepath.Base(arg), arg)
}

// readVEX reads the VEX document at path, named name, checking it loads.
func readVEX(name, path string) (VEXDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VEXDocument{}, fmt.Errorf("read %s: %w", path, err)
	}
	doc := VEXDocument{Name: name, Data: data}
	if _, err := LoadVEXDocuments([]VEXDocument{doc}); err != nil {
		return VEXDocument{}, err
	}
	return doc, nil
}

// RemoveVEX removes name from baseDir's managed VEX store, deleting its
// stored copy unless another name still refers to the same content. It
// refuses while a scan policy rule refers to name, so no rule is left
// pointing at nothing.
func RemoveVEX(baseDir, name string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}
	uses := func(r Rule) bool { return slices.Contains(r.VEX, name) }
	if err := rules.Users(config, uses, ruleMatch, name, "VEX document", "scan policy"); err != nil {
		return err
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
