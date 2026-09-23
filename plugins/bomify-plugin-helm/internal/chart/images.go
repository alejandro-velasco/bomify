package chart

import (
	"fmt"
	"sort"

	"helm.sh/helm/v3/pkg/releaseutil"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// imageRef is one container image reference discoverImages found, plus a
// human-readable pointer to the manifest it came from (for error
// messages — see buildBOM).
type imageRef struct {
	Reference string
	Source    string
}

// discoverImages walks manifest — a multi-document rendered Kubernetes
// YAML string, e.g. a release's Manifest — for every image referenced by
// a Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod's pod spec, via its
// well-known locations (containers, initContainers, ephemeralContainers;
// see containerImages). A given image reference is only reported once,
// even if multiple manifests/containers use it.
//
// This is deliberately limited to those built-in kinds for now. A custom
// resource (an Argo Rollout, a Knative Service, ...) isn't inspected —
// podSpecFor's switch is where kind-specific handling for those will need
// to plug in, once there's a way to configure where in a given custom
// resource its pod spec (or image references directly) live.
func discoverImages(manifest string) ([]imageRef, error) {
	docs := releaseutil.SplitManifests(manifest)

	// SplitManifests keys its map by a synthetic "<index>: <path>" name
	// with no ordering guarantee once iterated; sort those keys first so
	// discoverImages' own output (and any error it returns) is
	// deterministic across runs of the same chart/values.
	docNames := make([]string, 0, len(docs))
	for docName := range docs {
		docNames = append(docNames, docName)
	}
	sort.Strings(docNames)

	seen := make(map[string]bool)
	var images []imageRef

	for _, docName := range docNames {
		doc := docs[docName]

		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(doc), &head); err != nil || head.Kind == "" {
			// Not a (parseable) Kubernetes object — e.g. a blank or
			// comment-only document, which SplitManifests still yields
			// its own entry for. Nothing to search here.
			continue
		}

		podSpec, err := podSpecFor(head.Kind, doc)
		if err != nil {
			return nil, fmt.Errorf("parse %s %q: %w", head.Kind, head.Metadata.Name, err)
		}
		if podSpec == nil {
			continue
		}

		source := head.Kind + "/" + head.Metadata.Name
		for _, ref := range containerImages(podSpec) {
			if seen[ref] {
				continue
			}
			seen[ref] = true
			images = append(images, imageRef{Reference: ref, Source: source})
		}
	}

	sort.Slice(images, func(i, j int) bool { return images[i].Reference < images[j].Reference })
	return images, nil
}

// podSpecFor unmarshals doc as kind and returns the *corev1.PodSpec its
// containers live under, or nil if kind isn't one of the built-in
// pod-spec-bearing kinds this plugin currently knows how to search.
func podSpecFor(kind, doc string) (*corev1.PodSpec, error) {
	switch kind {
	case "Deployment":
		var obj appsv1.Deployment
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		return &obj.Spec.Template.Spec, nil
	case "StatefulSet":
		var obj appsv1.StatefulSet
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		return &obj.Spec.Template.Spec, nil
	case "DaemonSet":
		var obj appsv1.DaemonSet
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		return &obj.Spec.Template.Spec, nil
	case "Job":
		var obj batchv1.Job
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		return &obj.Spec.Template.Spec, nil
	case "CronJob":
		var obj batchv1.CronJob
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		return &obj.Spec.JobTemplate.Spec.Template.Spec, nil
	case "Pod":
		var obj corev1.Pod
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		return &obj.Spec, nil
	default:
		return nil, nil
	}
}

// containerImages returns every non-empty image reference from spec's
// init, regular, and ephemeral containers — bomify's "known locations"
// for a pod spec, in that order.
func containerImages(spec *corev1.PodSpec) []string {
	var refs []string

	for _, c := range spec.InitContainers {
		if c.Image != "" {
			refs = append(refs, c.Image)
		}
	}
	for _, c := range spec.Containers {
		if c.Image != "" {
			refs = append(refs, c.Image)
		}
	}
	for _, c := range spec.EphemeralContainers {
		if c.Image != "" {
			refs = append(refs, c.Image)
		}
	}

	return refs
}
