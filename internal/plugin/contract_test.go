package plugin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/testutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

func TestFindChecksContractVersion(t *testing.T) {
	for name, tc := range map[string]struct {
		contracts string // FAKEPLUGIN_CONTRACTS
		wantErr   []string
	}{
		"speaks it":      {contracts: `{"component":1,"sbom":1}`},
		"other version":  {contracts: `{"component":2,"sbom":1}`, wantErr: []string{`"bomify-plugin-fake"`, "offers component v2, sbom v1", "bomify needs component v1"}},
		"other contract": {contracts: `{"security":1}`, wantErr: []string{"offers security v1", "bomify needs component v1"}},
		"none":           {contracts: `{}`, wantErr: []string{"offers no contracts"}},
		// A plugin built before contract versions has no "contract"
		// subcommand at all.
		"predates them": {contracts: "unsupported", wantErr: []string{"predates them", `bomify plugin install fake`}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("FAKEPLUGIN_CONTRACTS", tc.contracts)
			dir := t.TempDir()
			testutil.InstallFakePlugin(t, dir, "fake")

			_, err := Find(dir, "fake", pluginlib.ComponentContract)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Find: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Find: nil, want error")
			}
			if !errors.Is(err, ErrIncompatible) || errors.Is(err, ErrNotInstalled) {
				t.Errorf("Find: %v, want it to wrap ErrIncompatible and not ErrNotInstalled", err)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Find: %v, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestFindMissingIsNotInstalled(t *testing.T) {
	if _, err := Find(t.TempDir(), "fake", pluginlib.ComponentContract); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("Find of a missing plugin: %v, want ErrNotInstalled", err)
	}
}

func TestFindAsksOncePerBinary(t *testing.T) {
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("FAKEPLUGIN_CONTRACT_LOG", calls)
	dir := t.TempDir()
	path := testutil.InstallFakePlugin(t, dir, "fake")

	count := func() int {
		data, _ := os.ReadFile(calls)
		return strings.Count(string(data), "\n")
	}

	for range 3 {
		if _, err := Find(dir, "fake", pluginlib.ComponentContract); err != nil {
			t.Fatal(err)
		}
	}
	// The answer covers every contract, so finding it for another doesn't
	// ask again either.
	if _, err := Find(dir, "fake", pluginlib.SecurityContract); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 1 {
		t.Errorf("asked %d times, want 1", got)
	}

	// A binary replaced mid-run is asked again.
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(dir, "fake", pluginlib.ComponentContract); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 2 {
		t.Errorf("after replacing the binary, asked %d times, want 2", got)
	}
}

// TestFindConcurrentlyAsksOnce has many callers find one plugin at once,
// as concurrent component pulls do: they share a single "contract" call.
func TestFindConcurrentlyAsksOnce(t *testing.T) {
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("FAKEPLUGIN_CONTRACT_LOG", calls)
	dir := t.TempDir()
	testutil.InstallFakePlugin(t, dir, "fake")

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Find(dir, "fake", pluginlib.ComponentContract)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	data, _ := os.ReadFile(calls)
	if got := strings.Count(string(data), "\n"); got != 1 {
		t.Errorf("asked %d times, want 1", got)
	}
}

func TestCheckCompatible(t *testing.T) {
	for name, tc := range map[string]struct {
		offered map[string]int
		wantErr string
	}{
		"every contract":       {offered: map[string]int{"component": 1, "sbom": 1, "security": 1, "signing": 1}},
		"one contract":         {offered: map[string]int{"signing": 1}},
		"unknown contract too": {offered: map[string]int{"component": 1, "deploy": 3}},
		"one at another version": {
			offered: map[string]int{"component": 1, "sbom": 2},
			wantErr: "bomify needs sbom v1",
		},
		"only unknown contracts": {offered: map[string]int{"deploy": 1}, wantErr: "none of which bomify speaks"},
		"nothing":                {offered: nil, wantErr: "offers no contracts"},
	} {
		err := CheckCompatible("bomify-plugin-fake", tc.offered)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, ErrIncompatible) {
			t.Errorf("%s: %v, want an ErrIncompatible containing %q", name, err, tc.wantErr)
		}
	}
}

func TestOfferedBy(t *testing.T) {
	with := func(value string) cdx.Component {
		return cdx.Component{Properties: &[]cdx.Property{{Name: "other", Value: "x"}, {Name: PropertyContracts, Value: value}}}
	}

	offered, ok, err := OfferedBy(with(`{"component":1}`))
	if err != nil || !ok || offered["component"] != 1 {
		t.Errorf("OfferedBy = %v, %v, %v; want component v1", offered, ok, err)
	}
	if _, ok, err := OfferedBy(cdx.Component{}); ok || err != nil {
		t.Errorf("OfferedBy of a component with no properties = %v, %v; want false, nil", ok, err)
	}
	if _, _, err := OfferedBy(with("not json")); err == nil {
		t.Error("OfferedBy of a malformed property: nil, want error")
	}
}
