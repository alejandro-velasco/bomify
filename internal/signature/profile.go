package signature

import (
	"errors"
	"fmt"
	"slices"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/rules"
)

// Profile is one entry in "<baseDir>/conf/signers.json": a named way to
// sign, which `bomify push`/`save --signer <name>` use. It holds options,
// such as a private key's path, never key material.
type Profile struct {
	Name string `json:"name"`
	// Kind names the signing plugin, bomify-plugin-<Kind>.
	Kind string `json:"kind"`
	// Options are passed through, unparsed, as --option flags to Kind's
	// "signature sign" and "signature attest".
	Options []string `json:"options,omitempty"`
}

// Plugin returns the plugin and options that sign as p.
func (p Profile) Plugin() Plugin {
	return Plugin{Kind: p.Kind, Options: p.Options}
}

func profileFile(baseDir string) rules.File[Profile] {
	return rules.File[Profile]{
		Path: layout.SignersConfig(baseDir),
		Key:  func(p Profile) string { return fmt.Sprintf("name=%q", p.Name) },
	}
}

// ReadProfiles returns baseDir's signing profiles, none if it has no
// signers.json yet.
func ReadProfiles(baseDir string) ([]Profile, error) {
	return profileFile(baseDir).Read()
}

// SetProfile adds p to baseDir's signers.json, replacing the profile of
// the same name.
func SetProfile(baseDir string, p Profile) error {
	if p.Name == "" {
		return errors.New("a signer needs a name")
	}
	if p.Kind == "" {
		return fmt.Errorf("signer %q has no plugin", p.Name)
	}
	return profileFile(baseDir).Set(p)
}

// RemoveProfile removes the profile called name from baseDir's
// signers.json, failing if there's none.
func RemoveProfile(baseDir, name string) error {
	return profileFile(baseDir).Remove(Profile{Name: name})
}

// FindProfile returns the profile called name among profiles.
func FindProfile(profiles []Profile, name string) (Profile, bool) {
	i := slices.IndexFunc(profiles, func(p Profile) bool { return p.Name == name })
	if i < 0 {
		return Profile{}, false
	}
	return profiles[i], true
}
