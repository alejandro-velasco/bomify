package chart

import (
	"strings"
	"testing"
)

func TestDiscoverImagesKnownKinds(t *testing.T) {
	manifest := strings.Join([]string{
		`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      initContainers:
      - name: init
        image: repo/init:1.0
      containers:
      - name: web
        image: repo/web:1.0
`,
		`apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  template:
    spec:
      containers:
      - name: db
        image: repo/db:1.0
`,
		`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent
spec:
  template:
    spec:
      containers:
      - name: agent
        image: repo/agent:1.0
`,
		`apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
spec:
  template:
    spec:
      containers:
      - name: migrate
        image: repo/migrate:1.0
`,
		`apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: repo/backup:1.0
`,
		`apiVersion: v1
kind: Pod
metadata:
  name: standalone
spec:
  containers:
  - name: standalone
    image: repo/standalone:1.0
`,
		// Re-uses "repo/web:1.0" from the Deployment above, to prove
		// duplicate references across manifests are only reported once.
		`apiVersion: v1
kind: Pod
metadata:
  name: duplicate
spec:
  containers:
  - name: duplicate
    image: repo/web:1.0
`,
		// An unrelated kind with no pod spec at all; must be silently
		// skipped rather than erroring the whole run.
		`apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
data:
  key: value
`,
	}, "\n---\n")

	images, err := discoverImages(manifest)
	if err != nil {
		t.Fatalf("discoverImages() error = %v", err)
	}

	want := []string{
		"repo/agent:1.0",
		"repo/backup:1.0",
		"repo/db:1.0",
		"repo/init:1.0",
		"repo/migrate:1.0",
		"repo/standalone:1.0",
		"repo/web:1.0",
	}

	if len(images) != len(want) {
		t.Fatalf("discoverImages() returned %d images, want %d: %+v", len(images), len(want), images)
	}
	for i, w := range want {
		if images[i].Reference != w {
			t.Errorf("images[%d].Reference = %q, want %q", i, images[i].Reference, w)
		}
	}
}

func TestDiscoverImagesEphemeralContainers(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: debug-target
spec:
  containers:
  - name: app
    image: repo/app:1.0
  ephemeralContainers:
  - name: debugger
    image: repo/debug:1.0
`

	images, err := discoverImages(manifest)
	if err != nil {
		t.Fatalf("discoverImages() error = %v", err)
	}

	want := []string{"repo/app:1.0", "repo/debug:1.0"}
	if len(images) != len(want) {
		t.Fatalf("discoverImages() = %+v, want %v", images, want)
	}
	for i, w := range want {
		if images[i].Reference != w {
			t.Errorf("images[%d].Reference = %q, want %q", i, images[i].Reference, w)
		}
	}
}

func TestDiscoverImagesMalformedKnownKindErrors(t *testing.T) {
	// "containers" is a mapping here instead of a list, so unmarshaling
	// into appsv1.Deployment must fail — discoverImages should surface
	// that rather than silently skipping it, since this is a kind it does
	// claim to understand.
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: broken
spec:
  template:
    spec:
      containers: "not-a-list"
`

	if _, err := discoverImages(manifest); err == nil {
		t.Fatal("discoverImages() error = nil, want an error for a malformed Deployment")
	}
}

func TestContainerImagesOrderAndEmptyImagesSkipped(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: mixed
spec:
  initContainers:
  - name: init
    image: repo/init:1.0
  - name: no-image
  containers:
  - name: main
    image: repo/main:1.0
  ephemeralContainers:
  - name: debug
    image: repo/debug:1.0
`

	images, err := discoverImages(manifest)
	if err != nil {
		t.Fatalf("discoverImages() error = %v", err)
	}

	// discoverImages sorts its final result, so check the set/order via
	// the sorted output directly.
	want := []string{"repo/debug:1.0", "repo/init:1.0", "repo/main:1.0"}
	if len(images) != len(want) {
		t.Fatalf("discoverImages() = %+v, want %v", images, want)
	}
	for i, w := range want {
		if images[i].Reference != w {
			t.Errorf("images[%d].Reference = %q, want %q", i, images[i].Reference, w)
		}
	}
}
