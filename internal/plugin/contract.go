package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/sliceutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// PropertyContracts is the CycloneDX property on a plugin package's
// PurlType component that records its binary's contract versions, as
// the JSON object its "contract" subcommand prints under "contracts"
// (e.g. {"component":1}). "bomify plugin install" checks it (see
// CheckOffered) before installing the binary.
const PropertyContracts = "land.bomify.plugin.contracts"

// ErrIncompatible is what Find's error wraps when the plugin is
// installed but doesn't speak the version of the contract bomify needs,
// or can't say which it speaks. CheckOffered's and CheckCompatible's
// errors wrap it too.
var ErrIncompatible = errors.New("incompatible")

// contractCache holds each plugin binary's answer to "contract", so a
// binary is asked once per run however many times it's found.
var (
	contractMu    sync.Mutex
	contractCache = map[binaryKey]*contractAnswer{}
)

// binaryKey identifies a plugin binary as it is now: a binary replaced
// mid-run (e.g. by "bomify plugin install") changes size or modification
// time, so it's asked again rather than trusted on its predecessor's
// answer.
type binaryKey struct {
	path    string
	size    int64
	modTime int64 // UnixNano
}

// contractAnswer is one binary's answer to "contract". once makes
// concurrent callers share a single invocation, which runs outside
// contractMu so asking one plugin never holds up another.
type contractAnswer struct {
	once     sync.Once
	versions map[string]int
	err      error
}

// cachedAnswer returns key's entry in contractCache, adding an empty one
// if there isn't one yet.
func cachedAnswer(key binaryKey) *contractAnswer {
	contractMu.Lock()
	defer contractMu.Unlock()
	answer, ok := contractCache[key]
	if !ok {
		answer = &contractAnswer{}
		contractCache[key] = answer
	}
	return answer
}

// checkContract fails unless the plugin binary at path, of kind, speaks
// the version of contract bomify needs, asking it (once; see
// contractCache) with its "contract" subcommand.
func checkContract(path, kind string, info os.FileInfo, contract pluginlib.Contract) error {
	answer := cachedAnswer(binaryKey{path: path, size: info.Size(), modTime: info.ModTime().UnixNano()})
	answer.once.Do(func() {
		var result pluginlib.ContractResult
		result, answer.err = Invoke[pluginlib.ContractResult](path, pluginlib.ContractSubcommand)
		answer.versions = result.Contracts
	})

	if answer.err != nil {
		return fmt.Errorf("plugin %q is %w: it can't report which plugin contract versions it speaks, so it predates them; upgrade it (\"bomify plugin install %s\"): %w", BinaryName(kind), ErrIncompatible, kind, answer.err)
	}
	return CheckOffered(BinaryName(kind), answer.versions, contract)
}

// CheckOffered fails unless offered — the contract versions the plugin
// name reports, as its "contract" subcommand does — includes the version
// of contract bomify needs, naming both if not.
func CheckOffered(name string, offered map[string]int, contract pluginlib.Contract) error {
	need := pluginlib.ContractVersions[contract]
	if offered[string(contract)] == need {
		return nil
	}
	return fmt.Errorf("plugin %q is %w: it offers %s, but bomify needs %s v%d", name, ErrIncompatible, formatOffered(offered), contract, need)
}

// CheckCompatible fails unless every contract bomify knows that offered
// includes is at the version bomify speaks, and offered includes at
// least one. A plugin package's binary is checked this way before it's
// installed: bomify can't yet know which contract it will be used
// through, so any it can't use refuses it.
func CheckCompatible(name string, offered map[string]int) error {
	known := 0
	for contract, need := range pluginlib.ContractVersions {
		got, ok := offered[string(contract)]
		if !ok {
			continue
		}
		if got != need {
			return fmt.Errorf("plugin %q is %w: it offers %s, but bomify needs %s v%d", name, ErrIncompatible, formatOffered(offered), contract, need)
		}
		known++
	}
	if known == 0 {
		return fmt.Errorf("plugin %q is %w: it offers %s, none of which bomify speaks", name, ErrIncompatible, formatOffered(offered))
	}
	return nil
}

// OfferedBy reads the contract versions component's PropertyContracts
// records, reporting false if it has none.
func OfferedBy(component cdx.Component) (map[string]int, bool, error) {
	for _, p := range sliceutil.Deref(component.Properties) {
		if p.Name != PropertyContracts {
			continue
		}
		var offered map[string]int
		if err := json.Unmarshal([]byte(p.Value), &offered); err != nil {
			return nil, true, fmt.Errorf("parse %s property: %w", PropertyContracts, err)
		}
		return offered, true, nil
	}
	return nil, false, nil
}

// formatOffered describes offered for an error message, e.g. "component
// v1, sbom v1", sorted by contract.
func formatOffered(offered map[string]int) string {
	if len(offered) == 0 {
		return "no contracts"
	}
	names := make([]string, 0, len(offered))
	for name := range offered {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = fmt.Sprintf("%s v%d", name, offered[name])
	}
	return strings.Join(parts, ", ")
}
