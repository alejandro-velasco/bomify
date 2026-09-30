package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// StoredVEX is one VEX document in a data directory's managed store (see
// AddVEX): an immutable copy of the file it was added from, named so
// scan policy rules can refer to it (see Rule.VEX).
type StoredVEX struct {
	// Name is how rules and "bomify security vex" refer to the document.
	Name string `json:"name"`
	// SHA256 is the stored copy's content hash, and so its file name (see
	// VEXPath).
	SHA256 string `json:"sha256"`
	// Source is the path it was added from, purely informational: the
	// store never reads it again.
	Source string `json:"source"`
	// Added is when it was added (or last replaced), as RFC 3339.
	Added string `json:"added"`
}

// VEXDir returns the directory baseDir's managed VEX documents live in.
func VEXDir(baseDir string) string {
	return filepath.Join(baseDir, "vex")
}

// VEXPath returns the path of the stored VEX document whose content
// hashes to sha256.
func VEXPath(baseDir, sha256 string) string {
	return filepath.Join(VEXDir(baseDir), sha256+".vex")
}

func vexIndexPath(baseDir string) string {
	return filepath.Join(VEXDir(baseDir), "index.json")
}

// ListVEX returns every document in baseDir's managed VEX store, sorted
// by name.
func ListVEX(baseDir string) ([]StoredVEX, error) {
	path := vexIndexPath(baseDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var index []StoredVEX
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	slices.SortFunc(index, func(a, b StoredVEX) int { return strings.Compare(a.Name, b.Name) })
	return index, nil
}

// AddVEX copies the VEX document at path into baseDir's managed store
// under name — after checking it loads (see LoadVEX) — replacing
// whatever name referred to before. The copy is content-addressed, so
// later edits to path don't reach the store until it's added again, and
// a scan decision can always be traced to the exact document behind it.
func AddVEX(baseDir, name, path string) (StoredVEX, error) {
	if err := validateVEXName(name); err != nil {
		return StoredVEX{}, err
	}
	if _, err := LoadVEX([]string{path}); err != nil {
		return StoredVEX{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return StoredVEX{}, fmt.Errorf("read %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	if err := writeFileAtomic(VEXPath(baseDir, hash), data); err != nil {
		return StoredVEX{}, err
	}

	source, err := filepath.Abs(path)
	if err != nil {
		source = path
	}
	entry := StoredVEX{
		Name:   name,
		SHA256: hash,
		Source: source,
		Added:  time.Now().UTC().Format(time.RFC3339),
	}

	index, err := ListVEX(baseDir)
	if err != nil {
		return StoredVEX{}, err
	}
	// replacedHash is the content name referred to before, if it existed.
	var replacedHash string
	i := slices.IndexFunc(index, func(e StoredVEX) bool { return e.Name == name })
	if i < 0 {
		index = append(index, entry)
	} else {
		replacedHash = index[i].SHA256
		index[i] = entry
	}

	if err := writeVEXIndex(baseDir, index); err != nil {
		return StoredVEX{}, err
	}
	if replacedHash != "" {
		removeUnreferencedVEX(baseDir, index, replacedHash)
	}
	return entry, nil
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

	index, err := ListVEX(baseDir)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(index, func(e StoredVEX) bool { return e.Name == name })
	if i < 0 {
		return fmt.Errorf("no such VEX document: %q", name)
	}
	removed := index[i]
	index = slices.Delete(index, i, i+1)

	if err := writeVEXIndex(baseDir, index); err != nil {
		return err
	}
	removeUnreferencedVEX(baseDir, index, removed.SHA256)
	return nil
}

// ResolveVEX returns the stored copy's path for each of names, in order,
// failing on any name not in baseDir's managed store.
func ResolveVEX(baseDir string, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	index, err := ListVEX(baseDir)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(index, func(e StoredVEX) bool { return e.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("no such VEX document: %q (see \"bomify security vex add\")", name)
		}
		paths = append(paths, VEXPath(baseDir, index[i].SHA256))
	}
	return paths, nil
}

// validateVEXName rejects names that couldn't be told apart from flags or
// lists: empty, or containing whitespace or commas.
func validateVEXName(name string) error {
	if name == "" || strings.ContainsFunc(name, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) || strings.HasPrefix(name, "-") {
		return fmt.Errorf("invalid VEX document name %q: must be non-empty, not start with \"-\", and contain no whitespace or commas", name)
	}
	return nil
}

// removeUnreferencedVEX deletes the stored copy hashing to sha256 unless
// an entry in index still refers to it. Best-effort: a copy left behind
// is harmless, just unused.
func removeUnreferencedVEX(baseDir string, index []StoredVEX, sha256 string) {
	if slices.ContainsFunc(index, func(e StoredVEX) bool { return e.SHA256 == sha256 }) {
		return
	}
	os.Remove(VEXPath(baseDir, sha256))
}

func writeVEXIndex(baseDir string, index []StoredVEX) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if index == nil {
		index = []StoredVEX{}
	}
	if err := enc.Encode(index); err != nil {
		return fmt.Errorf("marshal VEX index: %w", err)
	}
	return writeFileAtomic(vexIndexPath(baseDir), buf.Bytes())
}

// wildcardMatch renders a rule's Match as "bomify security policy list"
// does: "*" for one that applies to every package.
func wildcardMatch(match string) string {
	if match == "" {
		return "*"
	}
	return match
}
