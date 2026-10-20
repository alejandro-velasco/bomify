//! bomify-plugin-huggingface: pkg:huggingface models for bomify, on
//! Hugging Face's own hf-hub client. It implements the component and SBOM
//! generation plugin contracts (plugins/contracts/component/v1 and
//! plugins/contracts/sbom/v1).

mod hash;
mod hub;
mod log;
mod refs;
mod sbom;
mod token;
mod transfer;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Args, Parser, Subcommand};
use serde::Serialize;

use crate::hub::Hub;
use crate::log::Logger;
use crate::refs::Ref;

#[derive(Parser)]
#[command(
    name = "bomify-plugin-huggingface",
    about = "bomify plugin for Hugging Face Hub models"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Component plugin subcommands (pull/pack) — see plugins/contracts/component/v1/CONTRACT.md
    Component {
        #[command(subcommand)]
        command: ComponentCommand,
    },
    /// SBOM generation subcommands — see plugins/contracts/sbom/v1/CONTRACT.md
    Sbom {
        #[command(subcommand)]
        command: SbomCommand,
    },
    /// Print the plugin contracts this plugin implements and their versions
    Contract,
}

// The contracts' boolean flags take "--check", "--check=true", or
// "--check=false" (never "--check false", which would read "false" as an
// argument), so each says: an optional value (num_args), only after "="
// (require_equals), "false" when the flag is missing (default_value), and
// "true" when it's given bare (default_missing_value).

#[derive(Subcommand)]
enum ComponentCommand {
    /// Download the model repository at the purl's commit from the Hub
    Pull {
        #[command(flatten)]
        common: CommonFlags,
        /// directory to save the pulled component into (required unless --check)
        #[arg(long)]
        output: Option<PathBuf>,
        /// verify the component exists and is pullable without downloading it
        #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_value = "false", default_missing_value = "true")]
        check: bool,
    },
    /// Report that a model has no registry format of its own: bomify packages it as ModelPack
    Pack {
        #[command(flatten)]
        common: CommonFlags,
        /// directory a prior pull wrote the component into
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Args)]
struct CommonFlags {
    /// component purl
    #[arg(long)]
    purl: String,
    /// file to write plugin logs to
    #[arg(long)]
    log: String,
    /// enable ANSI color codes in the log output
    #[arg(long = "log-color", action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_value = "false", default_missing_value = "true")]
    log_color: bool,
}

const GENERATE_LONG: &str = r#"Generate describes a Hugging Face Hub model as a CycloneDX SBOM (JSON)
printed to stdout (--output redirects it to a file instead): one
machine-learning-model component, both what the SBOM describes and what
"bomify build" packages, with a pkg:huggingface purl pinned to the
commit the revision resolves to, so builds from it are reproducible.

Its SHA-256 is the tree hash "component pull" reports, computed from the
Hub's file listing: only files stored in Git, which are small, are
downloaded, never the weights. Its model card records the Hub's task,
architecture, and training datasets, as data rather than components to
package; its licenses, supplier, and base model come from the model
card's metadata too.

The model is described by --config, an options file, JSON or YAML.
Without --config, "bomify-huggingface-sbom.yaml" is read from the working
directory if present. Its keys, of which only model is required:

  model            the model repository, <namespace>/<name>
  revision         branch, tag, or commit; "main" if omitted
  repository-url   another hub, e.g. https://hub.example.com, recorded
                   as the purl's repository_url; $HF_ENDPOINT, or
                   huggingface.co, if omitted

A gated or private model needs a token: $HF_TOKEN, else one stored with
"bomify login <hub host> --verify=false", else "hf auth login"'s."#;

#[derive(Subcommand)]
enum SbomCommand {
    /// Describe a Hugging Face Hub model, pinned to a commit, with its hash and model card
    #[command(long_about = GENERATE_LONG)]
    Generate {
        /// the options, a JSON or YAML file
        #[arg(long, default_value = sbom::DEFAULT_CONFIG)]
        config: PathBuf,
        /// write the SBOM to this file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// The major version of each plugin contract this plugin implements, which
/// the "contract" command reports (see plugins/README.md#contract-versions).
const COMPONENT_CONTRACT_VERSION: u32 = 1;
const SBOM_CONTRACT_VERSION: u32 = 1;

/// The "contract" command's answer (see
/// plugins/contracts/contract-result.schema.json).
#[derive(Serialize)]
struct ContractResult {
    contracts: Contracts,
}

/// The contracts this plugin implements, each with the version it speaks.
#[derive(Serialize)]
struct Contracts {
    component: u32,
    sbom: u32,
}

fn contract_result() -> ContractResult {
    let contracts = Contracts {
        component: COMPONENT_CONTRACT_VERSION,
        sbom: SBOM_CONTRACT_VERSION,
    };
    ContractResult { contracts }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Contract => print_json(&contract_result()),
        Command::Component { command } => run_component(command),
        Command::Sbom {
            command: SbomCommand::Generate { config, output },
        } => run_generate(&config, output.as_deref()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // One line on stderr, per the contracts.
            eprintln!("{}", format!("{error:#}").replace('\n', " "));
            ExitCode::FAILURE
        }
    }
}

/// Runs a component subcommand: the one place that tells them apart, each
/// handing its own flags to its own function.
fn run_component(command: ComponentCommand) -> Result<()> {
    match command {
        ComponentCommand::Pull {
            common,
            output,
            check,
        } => with_reference(&common, |reference, logger| {
            run_pull(reference, output.as_deref(), check, logger)
        }),
        // The flags are the contract's, but a model has nothing to read
        // or write: bomify builds its ModelPack artifact itself.
        ComponentCommand::Pack { common, .. } => {
            with_reference(&common, |_, _| print_json(&PackResult {}))
        }
    }
}

/// What "component pack" prints, per the component contract: empty, as a
/// model's registry format, ModelPack, is bomify's to build.
#[derive(Serialize)]
struct PackResult {}

/// What every component subcommand does around its own work: opens the
/// log, resolves the purl, runs command on it, and logs a failure.
fn with_reference(
    common: &CommonFlags,
    command: impl FnOnce(&Ref, &Logger) -> Result<()>,
) -> Result<()> {
    let logger = Logger::open(&common.log, common.log_color)?;
    let outcome =
        resolve_purl(&common.purl, &logger).and_then(|reference| command(&reference, &logger));
    if let Err(error) = &outcome {
        logger.error("failed", &[("error", &format!("{error:#}"))]);
    }
    outcome
}

fn resolve_purl(purl: &str, logger: &Logger) -> Result<Ref> {
    logger.info("resolving purl", &[("purl", &purl)]);
    let reference = refs::resolve(purl)?;
    logger.info(
        "resolved repository",
        &[
            ("repository", &reference.repo_id()),
            ("revision", &reference.revision),
            ("endpoint", &reference.endpoint.as_deref().unwrap_or("")),
        ],
    );
    Ok(reference)
}

fn run_pull(reference: &Ref, output: Option<&Path>, check: bool, logger: &Logger) -> Result<()> {
    let hub = Hub::connect(reference.endpoint.as_deref(), logger)?;
    let result = if check {
        transfer::check_pull(&hub, reference)?
    } else {
        let Some(output) = output else {
            bail!("--output is required unless --check");
        };
        transfer::pull(&hub, reference, output, logger)?
    };
    print_json(&result)
}

fn run_generate(config: &Path, output: Option<&Path>) -> Result<()> {
    let options = sbom::read_options(config)?;
    let logger = Logger::stderr();
    let hub = Hub::connect(Some(&options.repository_url), &logger)?;
    let bom = sbom::generate(&hub, &options, &logger)?;
    let text = serde_json::to_string_pretty(&bom)?;
    match output {
        Some(path) => {
            std::fs::write(path, text + "\n").with_context(|| format!("write {}", path.display()))
        }
        None => print_line(&text),
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    print_line(&serde_json::to_string(value)?)
}

fn print_line(text: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_contracts() {
        let json = serde_json::to_string(&contract_result()).unwrap();
        assert_eq!(json, r#"{"contracts":{"component":1,"sbom":1}}"#);
    }
}
