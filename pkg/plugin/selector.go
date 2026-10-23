package plugin

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// MatchesSelector reports whether the component of purl, called name at
// version, is one selector names, as bomify names components on the
// command line ("bomify component pull") and a deployment plugin should
// in its options and templates:
//
//   - its purl, whole;
//   - its purl's type, namespace if it has one, and name, with or without
//     "pkg:" and "@<version>": "oci/podinfo", "helm/podinfo@6.7.1",
//     "pkg:huggingface/org/model@abc", its purl without qualifiers;
//   - its name, alone or as "<name>@<version>".
//
// A selector can name several components; see SelectComponent.
func MatchesSelector(purl, name, version, selector string) bool {
	if selector == "" {
		return false
	}
	if selector == purl || selector == name || selector == name+"@"+version {
		return true
	}
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		return false
	}
	path := parsed.Type + "/" + parsed.Name
	if parsed.Namespace != "" {
		path = parsed.Type + "/" + parsed.Namespace + "/" + parsed.Name
	}
	trimmed := strings.TrimPrefix(selector, "pkg:")
	return trimmed == path || trimmed == path+"@"+parsed.Version
}

// SelectComponent returns the one of components selector names (see
// MatchesSelector), failing if it names none, or several: the error then
// lists their purls, any of which names one alone.
func SelectComponent(components []DeploymentComponent, selector string) (DeploymentComponent, error) {
	var named []DeploymentComponent
	for _, component := range components {
		// A whole purl names one component, even if another shares
		// everything but its qualifiers.
		if component.Purl == selector {
			return component, nil
		}
		if MatchesSelector(component.Purl, component.Name, component.Version, selector) {
			named = append(named, component)
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(named) == 0 {
		return DeploymentComponent{}, fmt.Errorf("no component %q in the package", selector)
	}
	purls := make([]string, 0, len(named))
	for _, component := range named {
		purls = append(purls, component.Purl)
	}
	return DeploymentComponent{}, fmt.Errorf("%q names several components; name one by type and name, or by purl: %s", selector, strings.Join(purls, ", "))
}
