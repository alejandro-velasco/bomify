//! Reporting a pull's progress to the file its --progress names: one JSON
//! event per line, `{"name":"model.safetensors","current":1024,"total":4096}`.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hf_hub::progress::{DownloadEvent, FileStatus, ProgressEvent, ProgressHandler};
use serde::Serialize;

/// How often a file still downloading is reported, at most.
const INTERVAL: Duration = Duration::from_millis(100);

/// One line of the progress file.
#[derive(Serialize)]
struct Event<'a> {
    name: &'a str,
    current: u64,
    #[serde(skip_serializing_if = "is_zero")]
    total: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Reports each file hf-hub downloads: at most every INTERVAL while it
/// downloads, as hf-hub tells of every chunk, and once it's complete.
pub struct Progress {
    state: Mutex<State>,
}

struct State {
    output: Box<dyn Write + Send>,
    reported: HashMap<String, Instant>,
}

impl Progress {
    /// Progress appending to path.
    pub fn open(path: &str) -> Result<Progress> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open progress file {path}"))?;
        Ok(Progress::to(Box::new(file)))
    }

    fn to(output: Box<dyn Write + Send>) -> Progress {
        let state = State {
            output,
            reported: HashMap::new(),
        };
        Progress {
            state: Mutex::new(state),
        }
    }

    /// Reports current of name's total bytes (0 if unknown), unless it was
    /// reported less than INTERVAL ago and isn't complete.
    fn report(&self, name: &str, current: u64, total: u64, complete: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let now = Instant::now();
        if let Some(reported) = state.reported.get(name)
            && !complete
            && now.duration_since(*reported) < INTERVAL
        {
            return;
        }
        state.reported.insert(name.to_string(), now);

        let event = Event {
            name,
            current,
            total,
        };
        let Ok(mut line) = serde_json::to_string(&event) else {
            return;
        };
        line.push('\n');
        // Progress is only shown: a line that can't be written is no
        // reason to fail the pull.
        let _ = state.output.write_all(line.as_bytes());
    }
}

impl ProgressHandler for Progress {
    fn on_progress(&self, event: &ProgressEvent) {
        let ProgressEvent::Download(DownloadEvent::Progress { files }) = event else {
            return;
        };
        for file in files {
            let complete = file.status == FileStatus::Complete;
            // A complete file has all its bytes, whatever the event counts.
            let current = if complete && file.total_bytes > 0 {
                file.total_bytes
            } else {
                file.bytes_completed
            };
            self.report(&file.filename, current, file.total_bytes, complete);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_hub::progress::FileProgress;
    use std::sync::Arc;

    /// A writer whose bytes the test can read back.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn file(name: &str, current: u64, total: u64, status: FileStatus) -> ProgressEvent {
        let progress = FileProgress {
            filename: name.to_string(),
            bytes_completed: current,
            total_bytes: total,
            status,
        };
        ProgressEvent::Download(DownloadEvent::Progress {
            files: vec![progress],
        })
    }

    #[test]
    fn reports_a_file_at_once_then_at_most_every_interval_and_when_complete() {
        let output = Shared::default();
        let progress = Progress::to(Box::new(output.clone()));

        progress.on_progress(&file("model.safetensors", 1, 8, FileStatus::InProgress));
        progress.on_progress(&file("model.safetensors", 2, 8, FileStatus::InProgress));
        progress.on_progress(&file("model.safetensors", 3, 8, FileStatus::Complete));
        progress.on_progress(&ProgressEvent::Download(DownloadEvent::Complete));

        let written = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            written,
            "{\"name\":\"model.safetensors\",\"current\":1,\"total\":8}\n\
             {\"name\":\"model.safetensors\",\"current\":8,\"total\":8}\n"
        );
    }

    #[test]
    fn leaves_out_an_unknown_total() {
        let output = Shared::default();
        let progress = Progress::to(Box::new(output.clone()));

        progress.on_progress(&file("README.md", 0, 0, FileStatus::Complete));

        let written = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert_eq!(written, "{\"name\":\"README.md\",\"current\":0}\n");
    }
}
