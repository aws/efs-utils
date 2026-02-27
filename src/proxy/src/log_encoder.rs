use anyhow::Result;
use chrono::Utc;
use log4rs::encode::{Encode, Write};
use std::fmt;

/// Custom encoder that replaces newlines with spaces to keep multi-line logs on a single line
pub struct SingleLineEncoder;

impl Encode for SingleLineEncoder {
    fn encode(&self, w: &mut dyn Write, record: &log::Record<'_>) -> Result<()> {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let level = record.level();
        let module = record.module_path().unwrap_or("-");
        let message = format!("{}", record.args());
        let single_line_message = message.replace('\n', " ");

        writeln!(
            w,
            "{} {} {} {} {}",
            timestamp,
            std::process::id(),
            level,
            module,
            single_line_message
        )
        .map_err(|e| anyhow::anyhow!(e))
    }
}

impl fmt::Debug for SingleLineEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleLineEncoder").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::{Level, Record};
    use regex::Regex;
    use std::io;

    struct BufferWriter<'a>(&'a mut Vec<u8>);

    impl<'a> io::Write for BufferWriter<'a> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> Write for BufferWriter<'a> {
        // This trait is implemented automatically because BufferWriter implements io::Write
    }

    #[test]
    fn test_format_log_message() {
        let encoder = SingleLineEncoder;

        let record = Record::builder()
            .args(format_args!("Test message"))
            .level(Level::Info)
            .target("test_target")
            .module_path(Some("test_module"))
            .file(Some("test_file.rs"))
            .line(Some(42))
            .build();

        let mut buffer = Vec::new();

        let mut writer = BufferWriter(&mut buffer);
        encoder.encode(&mut writer, &record).unwrap();

        let output = String::from_utf8_lossy(&buffer);

        let timestamp_regex = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z";
        let pid_regex = r"\d+";
        let level_regex = r"INFO";
        let module_regex = r"test_module";
        let message_regex = r"Test message";

        let pattern = format!(
            "^{} {} {} {} {}$",
            timestamp_regex, pid_regex, level_regex, module_regex, message_regex
        );

        let regex = Regex::new(&pattern).unwrap();
        assert!(
            regex.is_match(output.trim()),
            "Output format doesn't match expected pattern. Got: {}",
            output
        );
    }

    #[test]
    fn test_multiline_message() {
        let encoder = SingleLineEncoder;

        let record = Record::builder()
            .args(format_args!("Test\nmultiline\nmessage"))
            .level(Level::Warn)
            .target("test_target")
            .module_path(Some("test_module"))
            .file(Some("test_file.rs"))
            .line(Some(42))
            .build();

        let mut buffer = Vec::new();

        let mut writer = BufferWriter(&mut buffer);
        encoder.encode(&mut writer, &record).unwrap();

        let output = String::from_utf8_lossy(&buffer);

        assert!(
            output.contains("Test multiline message"),
            "Multiline message not properly formatted. Got: {}",
            output
        );

        let newline_count = output.chars().filter(|&c| c == '\n').count();
        assert_eq!(
            newline_count, 1,
            "Expected only one newline at the end. Got: {}",
            output
        );
    }
}
