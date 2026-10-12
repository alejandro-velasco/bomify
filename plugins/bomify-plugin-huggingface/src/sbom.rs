//! sbom generate: a Hugging Face Hub model as a CycloneDX SBOM.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use hf_hub::repository::ModelInfo;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hash::{hash_content, hash_listing, verify};
use crate::hub::{Hub, RepoFile};
use crate::log::Logger;
use crate::refs::{DEFAULT_BRANCH, PURL_TYPE, Ref, is_commit_hash, repository_page, resolve};

/// The options file sbom generate reads when given no --config.
pub const DEFAULT_CONFIG: &str = "bomify-huggingface-sbom.yaml";

/// sbom generate's options. Unknown keys are refused, so a typo fails.
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// The model repository, "<namespace>/<name>".
    #[serde(default)]
    pub model: String,
    /// A branch, tag, or commit; main if empty.
    #[serde(default)]
    pub revision: String,
    /// Another hub, recorded as the purl's repository_url.
    #[serde(default, rename = "repository-url")]
    pub repository_url: String,
}

/// Reads the options file at path, JSON or YAML.
pub fn read_options(path: &Path) -> Result<Options> {
    let data = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    // YAML is a superset of JSON, so this reads both.
    let options: Options =
        serde_yaml_ng::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    if options.model.is_empty() {
        bail!(r#"required "model" not set in the options"#);
    }
    Ok(options)
}

/// A CycloneDX SBOM, as sbom generate prints it: one component, both the
/// SBOM's subject and its one component to package.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    #[serde(rename = "$schema")]
    schema: String,
    bom_format: String,
    spec_version: String,
    version: u32,
    metadata: Metadata,
    components: Vec<Component>,
}

#[derive(Serialize)]
struct Metadata {
    component: Component,
}

/// A CycloneDX machine-learning-model component.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Component {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<Supplier>,
    name: String,
    version: String,
    hashes: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<License>,
    purl: String,
    external_references: Vec<ExternalReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_card: Option<ModelCard>,
}

#[derive(Serialize, Clone)]
struct Supplier {
    name: String,
}

#[derive(Serialize, Clone)]
struct Hash {
    alg: String,
    content: String,
}

#[derive(Serialize, Clone)]
struct License {
    license: LicenseName,
}

#[derive(Serialize, Clone)]
struct LicenseName {
    name: String,
}

#[derive(Serialize, Clone)]
struct ExternalReference {
    url: String,
    #[serde(rename = "type")]
    kind: String,
}

impl ExternalReference {
    fn new(url: String, kind: &str) -> ExternalReference {
        ExternalReference {
            url,
            kind: kind.to_string(),
        }
    }
}

#[derive(Serialize, Clone)]
struct Property {
    name: String,
    value: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ModelCard {
    model_parameters: ModelParameters,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ModelParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    architecture_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_architecture: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    datasets: Vec<Dataset>,
}

#[derive(Serialize, Clone)]
struct Dataset {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    contents: DatasetContents,
}

#[derive(Serialize, Clone)]
struct DatasetContents {
    url: String,
}

/// An SBOM of the model options names, pinned to the commit the revision
/// resolves to, with its tree hash (computed from the Hub's listing,
/// downloading only files stored in Git) and a model card from the Hub's
/// metadata.
pub fn generate(hub: &Hub, options: &Options, logger: &Logger) -> Result<Bom> {
    let (namespace, name) = match options.model.split_once('/') {
        Some((namespace, name))
            if !namespace.is_empty() && !name.is_empty() && !name.contains('/') =>
        {
            (namespace, name)
        }
        _ => bail!("model {:?} isn't <namespace>/<name>", options.model),
    };
    let revision = if options.revision.is_empty() {
        DEFAULT_BRANCH
    } else {
        &options.revision
    };

    let info = hub
        .model(namespace, name)
        .info()
        .revision(revision.to_string())
        .send()
        .with_context(|| format!("read {}'s model info", options.model))?;
    let commit = info.sha.clone().unwrap_or_default();
    if !is_commit_hash(&commit) {
        bail!(
            "{}'s model info names commit {commit:?}, not a commit hash",
            options.model
        );
    }
    logger.info(
        "resolved revision",
        &[
            ("model", &options.model),
            ("revision", &revision),
            ("commit", &commit),
        ],
    );

    let reference = Ref {
        namespace: namespace.to_string(),
        name: name.to_string(),
        revision: commit,
        endpoint: Some(options.repository_url.clone()).filter(|url| !url.is_empty()),
    };
    let files = hub.list_files(&reference)?;
    let by_path: HashMap<&str, &RepoFile> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let paths: Vec<String> = files.iter().map(|file| file.path.clone()).collect();
    let hash = hash_listing(&paths, |path| file_sha256(hub, &reference, by_path[path]))?;

    let component = model_component(&reference, &hub.endpoint, &info, &hash, &by_path)?;
    let bom = Bom {
        schema: "http://cyclonedx.org/schema/bom-1.7.schema.json".to_string(),
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.7".to_string(),
        version: 1,
        metadata: Metadata {
            component: component.clone(),
        },
        components: vec![component],
    };
    Ok(bom)
}

/// A file's SHA-256: an LFS file's from the listing, any other's by
/// downloading it (such files are small), checked against its blob ID.
fn file_sha256(hub: &Hub, reference: &Ref, file: &RepoFile) -> Result<String> {
    if let Some(sha256) = &file.sha256 {
        return Ok(sha256.clone());
    }
    let content = hub
        .repository(reference)
        .download_file_to_bytes()
        .filename(file.path.clone())
        .revision(reference.revision.clone())
        .send()
        .with_context(|| format!("download {}", file.path))?;
    let hashes = hash_content(content.as_ref(), content.len() as u64)
        .with_context(|| format!("hash {}", file.path))?;
    verify(file, &hashes).with_context(|| format!("hash {}", file.path))?;
    Ok(hashes.sha256)
}

/// The model as a component whose purl and bom-ref is reference's, as
/// pull takes it.
fn model_component(
    reference: &Ref,
    endpoint: &str,
    info: &ModelInfo,
    tree_hash: &str,
    files: &HashMap<&str, &RepoFile>,
) -> Result<Component> {
    let mut purl = PackageUrl::new(PURL_TYPE, reference.name.clone()).context("build the purl")?;
    purl.with_namespace(reference.namespace.clone())
        .context("build the purl")?
        .with_version(reference.revision.clone())
        .context("build the purl")?;
    if let Some(repository_url) = &reference.endpoint {
        purl.add_qualifier("repository_url", repository_url.clone())
            .context("build the purl")?;
    }
    let purl = purl.to_string();
    resolve(&purl)?;

    let page = repository_page(endpoint, &reference.repo_id());
    let revision = &reference.revision;
    let mut references = vec![
        ExternalReference::new(page.clone(), "website"),
        ExternalReference::new(format!("{page}/tree/{revision}"), "distribution"),
    ];
    if files.contains_key("README.md") {
        let card = format!("{page}/blob/{revision}/README.md");
        references.push(ExternalReference::new(card, "model-card"));
    }

    let card = info.card_data.as_ref();
    let supplier = info
        .author
        .clone()
        .filter(|author| !author.is_empty())
        .map(|name| Supplier { name });
    let licenses = string_list(card, "license")
        .into_iter()
        .map(|name| License {
            license: LicenseName { name },
        })
        .collect();
    let base_models = string_list(card, "base_model");
    let mut properties = Vec::new();
    if !base_models.is_empty() {
        properties.push(Property {
            name: "huggingface:base_model".to_string(),
            value: base_models.join(","),
        });
    }
    let hash = Hash {
        alg: "SHA-256".to_string(),
        content: tree_hash.to_string(),
    };

    let component = Component {
        bom_ref: purl.clone(),
        kind: "machine-learning-model".to_string(),
        supplier,
        name: reference.name.clone(),
        version: reference.revision.clone(),
        hashes: vec![hash],
        licenses,
        purl,
        external_references: references,
        properties,
        model_card: model_card(endpoint, info),
    };
    Ok(component)
}

/// What the Hub says about the model: its task, architecture, and
/// training datasets, as data rather than components, since datasets
/// aren't packaged. None if the Hub says none of it.
fn model_card(endpoint: &str, info: &ModelInfo) -> Option<ModelCard> {
    let config = info.config.as_ref();
    let text = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    let datasets: Vec<Dataset> = string_list(info.card_data.as_ref(), "datasets")
        .into_iter()
        .map(|name| Dataset {
            kind: "dataset".to_string(),
            contents: DatasetContents {
                url: format!("{endpoint}/datasets/{name}"),
            },
            name,
        })
        .collect();
    let parameters = ModelParameters {
        task: info.pipeline_tag.clone().filter(|task| !task.is_empty()),
        architecture_family: text(config.and_then(|config| config.get("model_type"))),
        model_architecture: text(
            config
                .and_then(|config| config.get("architectures"))
                .and_then(|list| list.get(0)),
        ),
        datasets,
    };
    let empty = parameters.task.is_none()
        && parameters.architecture_family.is_none()
        && parameters.model_architecture.is_none()
        && parameters.datasets.is_empty();
    if empty {
        return None;
    }
    let card = ModelCard {
        model_parameters: parameters,
    };
    Some(card)
}

/// A model card field the Hub gives as one string or a list, as a list.
fn string_list(card: Option<&Value>, key: &str) -> Vec<String> {
    match card.and_then(|card| card.get(key)) {
        Some(Value::String(one)) if !one.is_empty() => vec![one.clone()],
        Some(Value::Array(many)) => many
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reads_string_or_list() {
        let card = json!({ "license": "mit", "datasets": ["a", "b"], "base_model": "" });
        assert_eq!(string_list(Some(&card), "license"), ["mit"]);
        assert_eq!(string_list(Some(&card), "datasets"), ["a", "b"]);
        assert!(string_list(Some(&card), "base_model").is_empty());
        assert!(string_list(Some(&card), "missing").is_empty());
        assert!(string_list(None, "license").is_empty());
    }

    #[test]
    fn refuses_unknown_options() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("options.json");
        std::fs::write(&path, r#"{"model": "org/model", "revison": "main"}"#).unwrap();
        assert!(read_options(&path).is_err());
        std::fs::write(&path, "model: org/model\nrevision: main\n").unwrap();
        let options = read_options(&path).unwrap();
        assert_eq!(
            (options.model.as_str(), options.revision.as_str()),
            ("org/model", "main")
        );
        std::fs::write(&path, "{}").unwrap();
        assert!(format!("{:#}", read_options(&path).unwrap_err()).contains(r#""model" not set"#));
    }
}
