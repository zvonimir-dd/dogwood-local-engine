//! Event histories read from a file, for the in-process `decide-last` command.
//!
//! Each entry pairs a [`WireEvent`] — the same shape `submit` sends — with the
//! time it happened, in epoch nanoseconds. This is **not** a wire type: the data
//! socket never accepts a caller-supplied timestamp, because the server's own
//! clock stamps every event it records. Only the file-only, stateless
//! `decide-last` command reads one.
//!
//! A history file is JSON Lines, one `{"ts": <ns>, "event": {…}}` per line
//! (blank lines are skipped), or a single JSON array of the same objects.

use serde::{Deserialize, Serialize};

use crate::protocol::WireEvent;

/// One event of a history and the time it happened (epoch nanoseconds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimedEvent {
    /// When the event happened, in epoch nanoseconds.
    pub ts: i64,
    /// The event, as `submit` would send it.
    pub event: WireEvent,
}

/// Parse a history: JSON Lines, or a JSON array if the first non-blank
/// character is `[`. Errors name the line (for JSON Lines) so a long file can
/// be fixed.
pub fn parse_history(src: &str) -> Result<Vec<TimedEvent>, String> {
    let trimmed = src.trim_start();
    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).map_err(|e| format!("events: {e}"));
    }
    src.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| {
            serde_json::from_str(line).map_err(|e| format!("events line {}: {e}", i + 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"{"ts": 5, "event": {"action": "Action::Read", "kind": "request", "principal": "User::\"alice\""}}"#;

    #[test]
    fn json_lines_skip_blank_lines() {
        let src = format!("{LINE}\n\n  \n{}\n", LINE.replace("\"ts\": 5", "\"ts\": 6"));
        let history = parse_history(&src).unwrap();
        assert_eq!(history.iter().map(|t| t.ts).collect::<Vec<_>>(), [5, 6]);
        assert_eq!(history[0].event.action, "Action::Read");
        assert_eq!(
            history[0].event.principal.as_deref(),
            Some("User::\"alice\"")
        );
    }

    #[test]
    fn a_json_array_is_accepted() {
        let history = parse_history(&format!("  [{LINE}, {LINE}]")).unwrap();
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn errors_name_the_line_and_unknown_fields_are_refused() {
        let bad = format!("{LINE}\n\n{{\"ts\": 1}}\n");
        assert!(
            parse_history(&bad)
                .unwrap_err()
                .starts_with("events line 3:")
        );
        let extra = LINE.replace("\"ts\": 5", "\"ts\": 5, \"at\": 1");
        assert!(parse_history(&extra).unwrap_err().contains("unknown field"));
    }

    #[test]
    fn an_empty_file_is_an_empty_history() {
        assert!(parse_history("\n\n").unwrap().is_empty());
    }
}
