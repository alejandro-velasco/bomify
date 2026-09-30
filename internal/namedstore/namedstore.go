// Package namedstore is a content-addressed store of files, each known
// by a name: the shape bomify's rule-referenced material takes in the
// data directory (VEX documents for scan policy rules, public keys for
// trust rules). Rules refer to an entry by name rather than to a file
// path, so they keep working however the originals move, and travel with
// the data directory. Each entry is an immutable copy — the only way its
// content changes is adding the name again.
//
// A store is a directory holding one "<sha256><ext>" file per distinct
// content, plus "index.json" mapping names to them. What counts as valid
// content, and which names rules still use, is the caller's business.
package namedstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
)

// Entry is one named file in a Store.
type Entry struct {
	// Name is how rules and commands refer to the entry.
	Name string `json:"name"`
	// SHA256 is the stored copy's content hash, and so its file name (see
	// Store.Path).
	SHA256 string `json:"sha256"`
	// Source is the path it was added from, purely informational: the
	// store never reads it again.
	Source string `json:"source"`
	// Added is when it was added (or last replaced), as RFC 3339.
	Added string `json:"added"`
}

// Store is one named, content-addressed store.
type Store struct {
	// Dir is the directory the store lives in.
	Dir string
	// Ext is the file extension stored copies get, e.g. ".vex".
	Ext string
	// Kind names what's stored, for messages, e.g. "VEX document".
	Kind string
}

// Path returns the path of the stored copy whose content hashes to
// sha256.
func (s Store) Path(sha256 string) string {
	return filepath.Join(s.Dir, sha256+s.Ext)
}

func (s Store) indexPath() string {
	return filepath.Join(s.Dir, "index.json")
}

// List returns every entry in s, sorted by name.
func (s Store) List() ([]Entry, error) {
	var index []Entry
	if err := fsutil.ReadJSON(s.indexPath(), &index); err != nil {
		return nil, err
	}
	slices.SortFunc(index, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return index, nil
}

// Add stores data — read from source, which is only recorded — under
// name, replacing whatever name referred to before. The caller checks
// data is valid first.
func (s Store) Add(name, source string, data []byte) (Entry, error) {
	if err := ValidateName(s.Kind, name); err != nil {
		return Entry{}, err
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if err := fsutil.WriteFileAtomic(s.Path(hash), data); err != nil {
		return Entry{}, err
	}

	if abs, err := filepath.Abs(source); err == nil {
		source = abs
	}
	entry := Entry{
		Name:   name,
		SHA256: hash,
		Source: source,
		Added:  time.Now().UTC().Format(time.RFC3339),
	}

	index, err := s.List()
	if err != nil {
		return Entry{}, err
	}

	// replacedHash is the content name referred to before, if it existed.
	var replacedHash string
	i := slices.IndexFunc(index, func(e Entry) bool { return e.Name == name })
	if i < 0 {
		index = append(index, entry)
	} else {
		replacedHash = index[i].SHA256
		index[i] = entry
	}

	if err := s.writeIndex(index); err != nil {
		return Entry{}, err
	}
	if replacedHash != "" {
		s.removeUnreferenced(index, replacedHash)
	}
	return entry, nil
}

// Remove drops name from s, deleting its stored copy unless another name
// still refers to the same content. The caller checks nothing still uses
// name first.
func (s Store) Remove(name string) error {
	index, err := s.List()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(index, func(e Entry) bool { return e.Name == name })
	if i < 0 {
		return fmt.Errorf("no such %s: %q", s.Kind, name)
	}
	removed := index[i]
	index = slices.Delete(index, i, i+1)

	if err := s.writeIndex(index); err != nil {
		return err
	}
	s.removeUnreferenced(index, removed.SHA256)
	return nil
}

// Resolve returns the stored copy's path for each of names, in order,
// failing on any name not in s.
func (s Store) Resolve(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	index, err := s.List()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(index, func(e Entry) bool { return e.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("no such %s: %q", s.Kind, name)
		}
		paths = append(paths, s.Path(index[i].SHA256))
	}
	return paths, nil
}

// ValidateName rejects names that couldn't be told apart from flags or
// lists: empty, starting with "-", or containing whitespace, commas, or
// "=".
func ValidateName(kind, name string) error {
	invalid := name == "" || strings.HasPrefix(name, "-") ||
		strings.ContainsFunc(name, func(r rune) bool {
			return r == ',' || r == '=' || r == ' ' || r == '\t' || r == '\n'
		})
	if invalid {
		return fmt.Errorf("invalid %s name %q: must be non-empty, not start with \"-\", and contain no whitespace, commas, or \"=\"", kind, name)
	}
	return nil
}

// removeUnreferenced deletes the stored copy hashing to sha256 unless an
// entry in index still refers to it. Best-effort: a copy left behind is
// harmless, just unused.
func (s Store) removeUnreferenced(index []Entry, sha256 string) {
	if slices.ContainsFunc(index, func(e Entry) bool { return e.SHA256 == sha256 }) {
		return
	}
	os.Remove(s.Path(sha256))
}

func (s Store) writeIndex(index []Entry) error {
	if index == nil {
		index = []Entry{}
	}
	return fsutil.WriteJSON(s.indexPath(), index)
}
