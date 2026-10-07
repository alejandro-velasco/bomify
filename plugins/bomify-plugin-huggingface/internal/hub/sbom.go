package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// modelInfo is the part of the Hub's model info
// (/api/models/{repo}/revision/{rev}) an SBOM records.
type modelInfo struct {
	// SHA is the commit the revision resolved to.
	SHA         string `json:"sha"`
	Author      string `json:"author"`
	PipelineTag string `json:"pipeline_tag"`
	Config      struct {
		ModelType     string   `json:"model_type"`
		Architectures []string `json:"architectures"`
	} `json:"config"`
	CardData struct {
		License   stringList `json:"license"`
		Datasets  stringList `json:"datasets"`
		BaseModel stringList `json:"base_model"`
	} `json:"cardData"`
}

// stringList is a model card field the Hub gives as one string or a list.
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*l = nil
		if one != "" {
			*l = []string{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

// ModelInfo returns repoID's model info at revision: a branch, tag, or
// commit.
func (c Client) ModelInfo(ctx context.Context, repoID, revision string) (modelInfo, error) {
	target := fmt.Sprintf("%s/api/models/%s/revision/%s", c.Endpoint, repoID, url.PathEscape(revision))
	response, err := c.get(ctx, http.MethodGet, target)
	if err != nil {
		return modelInfo{}, err
	}
	defer response.Body.Close()

	var info modelInfo
	if err := json.NewDecoder(response.Body).Decode(&info); err != nil {
		return modelInfo{}, fmt.Errorf("parse %s's model info: %w", repoID, err)
	}
	if !commitHash.MatchString(info.SHA) {
		return modelInfo{}, fmt.Errorf("%s's model info names commit %q, not a commit hash", repoID, info.SHA)
	}
	return info, nil
}

// fileSHA256 returns file's SHA-256: an LFS file's from the listing, any
// other's by downloading it (such files are small), checked against its
// blob ID.
func (c Client) fileSHA256(ctx context.Context, ref Ref, file File) (string, error) {
	if file.SHA256 != "" {
		return file.SHA256, nil
	}
	response, err := c.get(ctx, http.MethodGet, c.fileURL(ref, file))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	content := sha256.New()
	blob, wantBlob := verifier(file)
	if _, err := io.Copy(io.MultiWriter(content, blob), response.Body); err != nil {
		return "", fmt.Errorf("hash %s: %w", file.Path, err)
	}
	if got := hex.EncodeToString(blob.Sum(nil)); got != wantBlob {
		return "", fmt.Errorf("hash %s: got content hashing to %s, want %s", file.Path, got, wantBlob)
	}
	return hex.EncodeToString(content.Sum(nil)), nil
}

// GenerateOptions say which model Generate describes.
type GenerateOptions struct {
	// RepoID is "<namespace>/<name>".
	RepoID string
	// Revision is a branch, tag, or commit, pinned to its commit.
	Revision string
	// RepositoryURL, if set, is the hub, recorded as the purl's
	// repository_url.
	RepositoryURL string
}

// Generate returns an SBOM of the model options name: one
// machine-learning-model component, both the SBOM's subject and its one
// component to package, pinned to the commit the revision resolves to,
// with its TreeHash (computed from the Hub's listing, downloading only
// files stored in Git) and a model card from the Hub's metadata.
func Generate(ctx context.Context, hub Client, options GenerateOptions, logger *slog.Logger) (*cdx.BOM, error) {
	namespace, name, ok := strings.Cut(options.RepoID, "/")
	if !ok || namespace == "" || name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("model %q isn't <namespace>/<name>", options.RepoID)
	}
	revision := options.Revision
	if revision == "" {
		revision = "main"
	}

	info, err := hub.ModelInfo(ctx, options.RepoID, revision)
	if err != nil {
		return nil, err
	}
	logger.Info("resolved revision", "model", options.RepoID, "revision", revision, "commit", info.SHA)
	ref := Ref{
		Namespace: namespace,
		Name:      name,
		Revision:  info.SHA,
		Endpoint:  options.RepositoryURL,
	}

	files, err := hub.ListFiles(ctx, ref)
	if err != nil {
		return nil, err
	}
	byPath := map[string]File{}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		byPath[file.Path] = file
		paths = append(paths, file.Path)
	}
	hash, err := hashListing(paths, func(path string) (string, error) {
		return hub.fileSHA256(ctx, ref, byPath[path])
	})
	if err != nil {
		return nil, err
	}

	component, err := modelComponent(ref, hub.Endpoint, info, hash, byPath)
	if err != nil {
		return nil, err
	}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &component}
	bom.Components = &[]cdx.Component{component}
	return bom, nil
}

// modelComponent describes ref as a CycloneDX machine-learning-model
// component whose purl and bom-ref is ref's, as pull takes it.
func modelComponent(ref Ref, endpoint string, info modelInfo, treeHash string, files map[string]File) (cdx.Component, error) {
	var qualifiers packageurl.Qualifiers
	if ref.Endpoint != "" {
		qualifiers = packageurl.QualifiersFromMap(map[string]string{"repository_url": ref.Endpoint})
	}
	purl := packageurl.NewPackageURL(PurlType, ref.Namespace, ref.Name, ref.Revision, qualifiers, "").ToString()
	if _, err := Resolve(purl); err != nil {
		return cdx.Component{}, err
	}

	repositoryPage := endpoint + "/" + ref.RepoID()
	references := []cdx.ExternalReference{
		{Type: cdx.ERTypeWebsite, URL: repositoryPage},
		{Type: cdx.ERTypeDistribution, URL: repositoryPage + "/tree/" + ref.Revision},
	}
	if _, ok := files["README.md"]; ok {
		modelCard := cdx.ExternalReference{
			Type: cdx.ERTypeModelCard,
			URL:  repositoryPage + "/blob/" + ref.Revision + "/README.md",
		}
		references = append(references, modelCard)
	}

	component := cdx.Component{
		BOMRef:             purl,
		Type:               cdx.ComponentTypeMachineLearningModel,
		Name:               ref.Name,
		Version:            ref.Revision,
		PackageURL:         purl,
		Hashes:             &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: treeHash}},
		ExternalReferences: &references,
		ModelCard:          modelCard(endpoint, info),
	}
	if info.Author != "" {
		component.Supplier = &cdx.OrganizationalEntity{Name: info.Author}
	}
	if len(info.CardData.License) > 0 {
		licenses := cdx.Licenses{}
		for _, license := range info.CardData.License {
			licenses = append(licenses, cdx.LicenseChoice{License: &cdx.License{Name: license}})
		}
		component.Licenses = &licenses
	}
	if len(info.CardData.BaseModel) > 0 {
		property := cdx.Property{
			Name:  "huggingface:base_model",
			Value: strings.Join(info.CardData.BaseModel, ","),
		}
		component.Properties = &[]cdx.Property{property}
	}
	return component, nil
}

// modelCard records what the Hub says about the model: its task,
// architecture, and training datasets, as data rather than components,
// since datasets aren't packaged. Nil if the Hub says none of it.
func modelCard(endpoint string, info modelInfo) *cdx.MLModelCard {
	parameters := cdx.MLModelParameters{
		Task:               info.PipelineTag,
		ArchitectureFamily: info.Config.ModelType,
	}
	if len(info.Config.Architectures) > 0 {
		parameters.ModelArchitecture = info.Config.Architectures[0]
	}
	if len(info.CardData.Datasets) > 0 {
		datasets := make([]cdx.MLDatasetChoice, 0, len(info.CardData.Datasets))
		for _, dataset := range info.CardData.Datasets {
			data := cdx.ComponentData{
				Type:     cdx.ComponentDataTypeDataset,
				Name:     dataset,
				Contents: &cdx.ComponentDataContents{URL: endpoint + "/datasets/" + dataset},
			}
			datasets = append(datasets, cdx.MLDatasetChoice{ComponentData: &data})
		}
		parameters.Datasets = &datasets
	}

	if parameters.Task == "" && parameters.ArchitectureFamily == "" && parameters.ModelArchitecture == "" && parameters.Datasets == nil {
		return nil
	}
	return &cdx.MLModelCard{ModelParameters: &parameters}
}
