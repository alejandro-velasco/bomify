//! sbom generate: a Hugging Face Hub model as a CycloneDX SBOM.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use hf_hub::repository::ModelInfo;
use packageurl::PackageUrl;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::hub::{File, Hub, hash_content, hash_listing, verify};
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

/// An SBOM of the model options names: one machine-learning-model
/// component, both the SBOM's subject and its one component to package,
/// pinned to the commit the revision resolves to, with its tree hash
/// (computed from the Hub's listing, downloading only files stored in
/// Git) and a model card from the Hub's metadata.
pub fn generate(hub: &Hub, options: &Options, logger: &crate::log::Logger) -> Result<Value> {
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
            ("revision", revision),
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
    let by_path: HashMap<&str, &File> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let paths: Vec<String> = files.iter().map(|file| file.path.clone()).collect();
    let hash = hash_listing(&paths, |path| file_sha256(hub, &reference, by_path[path]))?;

    let component = model_component(&reference, &hub.endpoint, &info, &hash, &by_path)?;
    let bom = json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": { "component": component.clone() },
        "components": [component],
    });
    Ok(bom)
}

/// A file's SHA-256: an LFS file's from the listing, any other's by
/// downloading it (such files are small), checked against its blob ID.
fn file_sha256(hub: &Hub, reference: &Ref, file: &File) -> Result<String> {
    if let Some(sha256) = &file.sha256 {
        return Ok(sha256.clone());
    }
    let content = hub
        .model(&reference.namespace, &reference.name)
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

/// The model as a CycloneDX machine-learning-model component whose purl
/// and bom-ref is reference's, as pull takes it.
fn model_component(
    reference: &Ref,
    endpoint: &str,
    info: &ModelInfo,
    tree_hash: &str,
    files: &HashMap<&str, &File>,
) -> Result<Value> {
    let mut purl = PackageUrl::new(PURL_TYPE, reference.name.clone()).context("build the purl")?;
    purl.with_namespace(reference.namespace.clone())
        .with_version(reference.revision.clone());
    if let Some(repository_url) = &reference.endpoint {
        purl.add_qualifier("repository_url", repository_url.clone())
            .context("build the purl")?;
    }
    let purl = purl.to_string();
    resolve(&purl)?;

    let page = repository_page(endpoint, &reference.repo_id());
    let mut references = vec![
        json!({ "url": page, "type": "website" }),
        json!({ "url": format!("{page}/tree/{}", reference.revision), "type": "distribution" }),
    ];
    if files.contains_key("README.md") {
        references.push(json!({ "url": format!("{page}/blob/{}/README.md", reference.revision), "type": "model-card" }));
    }

    let card = info.card_data.as_ref();
    let mut component = serde_json::Map::new();
    component.insert("bom-ref".into(), json!(purl));
    component.insert("type".into(), json!("machine-learning-model"));
    if let Some(author) = info.author.as_ref().filter(|author| !author.is_empty()) {
        component.insert("supplier".into(), json!({ "name": author }));
    }
    component.insert("name".into(), json!(reference.name));
    component.insert("version".into(), json!(reference.revision));
    component.insert(
        "hashes".into(),
        json!([{ "alg": "SHA-256", "content": tree_hash }]),
    );
    let licenses = string_list(card, "license");
    if !licenses.is_empty() {
        let licenses: Vec<Value> = licenses
            .iter()
            .map(|license| json!({ "license": { "name": license } }))
            .collect();
        component.insert("licenses".into(), json!(licenses));
    }
    component.insert("purl".into(), json!(purl));
    component.insert("externalReferences".into(), json!(references));
    let base_models = string_list(card, "base_model");
    if !base_models.is_empty() {
        component.insert(
            "properties".into(),
            json!([{ "name": "huggingface:base_model", "value": base_models.join(",") }]),
        );
    }
    if let Some(model_card) = model_card(endpoint, info) {
        component.insert("modelCard".into(), model_card);
    }
    Ok(Value::Object(component))
}

/// What the Hub says about the model: its task, architecture, and
/// training datasets, as data rather than components, since datasets
/// aren't packaged. None if the Hub says none of it.
fn model_card(endpoint: &str, info: &ModelInfo) -> Option<Value> {
    let config = info.config.as_ref();
    let text = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    let task = info.pipeline_tag.clone().filter(|task| !task.is_empty());
    let family = text(config.and_then(|config| config.get("model_type")));
    let architecture = text(
        config
            .and_then(|config| config.get("architectures"))
            .and_then(|list| list.get(0)),
    );
    let datasets = string_list(info.card_data.as_ref(), "datasets");

    let mut parameters = serde_json::Map::new();
    if let Some(task) = task {
        parameters.insert("task".into(), json!(task));
    }
    if let Some(family) = family {
        parameters.insert("architectureFamily".into(), json!(family));
    }
    if let Some(architecture) = architecture {
        parameters.insert("modelArchitecture".into(), json!(architecture));
    }
    if !datasets.is_empty() {
        let datasets: Vec<Value> = datasets
            .iter()
            .map(|dataset| json!({ "type": "dataset", "name": dataset, "contents": { "url": format!("{endpoint}/datasets/{dataset}") } }))
            .collect();
        parameters.insert("datasets".into(), json!(datasets));
    }
    if parameters.is_empty() {
        return None;
    }
    Some(json!({ "modelParameters": parameters }))
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
