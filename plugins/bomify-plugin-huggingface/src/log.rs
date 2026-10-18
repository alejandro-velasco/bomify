//! Logging to the file a component command's --log names, in bomify's own
//! log format: "15:04:05 INF message key=value ...".

use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use anyhow::{Context, Result};

/// Writes log lines to a file, stderr, or nowhere.
pub struct Logger {
    output: Option<Mutex<Box<dyn Write + Send>>>,
    color: bool,
}

#[derive(Clone, Copy)]
enum Level {
    Info,
    Error,
}

impl Logger {
    /// A logger appending to path, with ANSI colors if color is set.
    pub fn open(path: &str, color: bool) -> Result<Logger> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file {path}"))?;
        let logger = Logger {
            output: Some(Mutex::new(Box::new(file))),
            color,
        };
        Ok(logger)
    }

    /// A logger writing to stderr, as sbom generate logs.
    pub fn stderr() -> Logger {
        Logger {
            output: Some(Mutex::new(Box::new(std::io::stderr()))),
            color: false,
        }
    }

    /// A logger that writes nothing.
    #[cfg(test)]
    pub fn discard() -> Logger {
        Logger {
            output: None,
            color: false,
        }
    }

    /// Logs message with attrs, key=value pairs whose values can be
    /// anything printable: `&[("files", &files.len())]`.
    pub fn info(&self, message: &str, attrs: &[(&str, &dyn Display)]) {
        self.write(Level::Info, message, attrs);
    }

    pub fn error(&self, message: &str, attrs: &[(&str, &dyn Display)]) {
        self.write(Level::Error, message, attrs);
    }

    fn write(&self, level: Level, message: &str, attrs: &[(&str, &dyn Display)]) {
        let Some(output) = &self.output else {
            return;
        };
        let line = self.format(level, message, attrs);
        if let Ok(mut output) = output.lock() {
            // A log line that can't be written is no reason to fail.
            let _ = output.write_all(line.as_bytes());
        }
    }

    fn format(&self, level: Level, message: &str, attrs: &[(&str, &dyn Display)]) -> String {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        let (name, color) = match level {
            Level::Info => ("INF", "92"),
            Level::Error => ("ERR", "91"),
        };
        let mut line = if self.color {
            format!("\x1b[2m{time}\x1b[0m \x1b[{color}m{name}\x1b[0m {message}")
        } else {
            format!("{time} {name} {message}")
        };
        for (key, value) in attrs {
            let value = quote(&value.to_string());
            if self.color {
                line.push_str(&format!(" \x1b[2m{key}=\x1b[0m{value}"));
            } else {
                line.push_str(&format!(" {key}={value}"));
            }
        }
        line.push('\n');
        line
    }
}

/// Quotes a value that wouldn't read as one token.
fn quote(value: &str) -> String {
    if value.is_empty() || value.contains([' ', '"', '=', '\n']) {
        format!("{value:?}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_lines() {
        let logger = Logger::discard();
        let line = logger.format(
            Level::Info,
            "pulled",
            &[("files", &21), ("message", &"a b")],
        );
        let (time, rest) = line.split_once(' ').unwrap();
        assert_eq!(time.len(), 8);
        assert_eq!(rest, "INF pulled files=21 message=\"a b\"\n");
    }
}
