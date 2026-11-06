//! `dogwood-server decide-last`, end to end through the real binary: the
//! stateless decision for a history file, its output, and its exit codes (0 on
//! allow, 1 on deny or error, like `submit`). No server is started.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use dogwood_local_engine::StatelessTemporalEngine;

const SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };
action Export appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };
"#;

const POLICY: &str = r#"
@id("base")
permit (principal, action, resource);

@id("cooldown")
@description("No export within an hour of a read.")
forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;

const T0: i64 = 1_700_000_000_000_000_000;
const HOUR: i64 = 3_600_000_000_000;

fn event(ts: i64, action: &str, kind: &str) -> String {
    format!(
        r#"{{"ts": {ts}, "event": {{"action": "Action::{action}", "kind": "{kind}", "principal": "User::\"alice\"", "resource": "Doc::\"d1\"", "logged": {{"input": {{"doc": "d1"}}}}, "context": {{"input": {{"doc": "d1"}}}}}}}}"#
    )
}

/// A scratch directory holding the policy, the schema and a history file.
struct Files {
    dir: PathBuf,
}

impl Files {
    fn new(tag: &str, history: &[String]) -> Self {
        let dir =
            std::env::temp_dir().join(format!("dogwood_decide_last_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("policy.dw"), POLICY).unwrap();
        std::fs::write(dir.join("schema.cedarschema"), SCHEMA).unwrap();
        std::fs::write(dir.join("events.jsonl"), history.join("\n") + "\n").unwrap();
        Files { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn run(&self, extra: &[&str]) -> Output {
        self.run_with_stdin(extra, None)
    }

    fn run_with_stdin(&self, extra: &[&str], stdin: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dogwood-server"));
        cmd.arg("decide-last")
            .arg(self.path("policy.dw"))
            .arg("--action-schema")
            .arg(self.path("schema.cedarschema"))
            .args(extra)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !extra.contains(&"--events") {
            cmd.arg("--events").arg(self.path("events.jsonl"));
        }
        let mut child = cmd.spawn().expect("the binary runs");
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn json_documents(bytes: &[u8]) -> Vec<serde_json::Value> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<serde_json::Value>()
        .collect::<Result<_, _>>()
        .expect("stdout is JSON")
}

#[test]
fn an_allowed_last_event_exits_zero() {
    let f = Files::new(
        "allow",
        &[
            event(T0, "Read", "response"),
            event(T0 + 2 * HOUR, "Export", "request"),
        ],
    );
    let out = f.run(&[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("ALLOW\n"), "{stdout}");
    assert!(
        stdout.contains(&format!("decided at: {}ns (event 2 of 2)", T0 + 2 * HOUR)),
        "{stdout}"
    );
    assert!(stdout.contains("determined by: base"), "{stdout}");
}

#[test]
fn a_denied_last_event_exits_one_and_names_the_rule() {
    let f = Files::new(
        "deny",
        &[
            event(T0, "Read", "response"),
            event(T0 + 60_000_000_000, "Export", "request"),
        ],
    );
    let out = f.run(&[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("DENY\n"), "{stdout}");
    assert!(
        stdout.contains("determined by: cooldown: No export within an hour of a read."),
        "{stdout}"
    );
    assert_eq!(text(&out.stderr), "dogwood-server: deny\n");
}

#[test]
fn json_output_reports_the_decision() {
    let f = Files::new(
        "json",
        &[
            event(T0, "Read", "response"),
            event(T0, "Export", "request"),
        ],
    );
    let out = f.run(&["--json"]);
    assert_eq!(out.status.code(), Some(1));
    let docs = json_documents(&out.stdout);
    let d = &docs[0];
    assert_eq!(d["status"], "decision");
    assert_eq!(d["allowed"], false);
    assert_eq!(
        d["decided_at_nanos"],
        T0 + 1,
        "the tie is spread one nanosecond"
    );
    assert_eq!(d["events"], 2);
    assert_eq!(d["reason"][0]["annotations"]["id"], "cooldown");
    assert_eq!(d["errors"], serde_json::json!([]));
    assert!(d.get("timings_us").is_none(), "timings only on request");
    assert_eq!(
        docs[1],
        serde_json::json!({"error": "deny"}),
        "like submit's --json deny"
    );
}

#[test]
fn timings_are_reported_when_asked() {
    let f = Files::new("timings", &[event(T0, "Export", "request")]);
    let out = f.run(&["--json", "--timings"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let docs = json_documents(&out.stdout);
    let t = &docs[0]["timings_us"];
    for key in ["compile", "decide", "total"] {
        assert!(t[key].as_u64().is_some(), "{key} in {t}");
    }
    let human = f.run(&["--timings"]);
    assert!(
        text(&human.stdout).contains("compiled in "),
        "{}",
        text(&human.stdout)
    );
}

#[test]
fn bad_histories_exit_one_with_the_reason() {
    let ends_in_history = Files::new("history_last", &[event(T0, "Read", "response")]);
    let out = ends_in_history.run(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("not a decision kind"),
        "{}",
        text(&out.stderr)
    );

    let backwards = Files::new(
        "backwards",
        &[
            event(T0 + 5, "Read", "response"),
            event(T0, "Export", "request"),
        ],
    );
    let out = backwards.run(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("in time order"),
        "{}",
        text(&out.stderr)
    );

    let malformed = Files::new(
        "malformed",
        &[event(T0, "Export", "request"), "{\"ts\": 1}".to_string()],
    );
    let out = malformed.run(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("events line 2:"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_bad_policy_reports_what_install_reports() {
    let f = Files::new("bad_policy", &[event(T0, "Export", "request")]);
    std::fs::write(f.path("policy.dw"), "permit (principal, action, resource").unwrap();
    let out = f.run(&[]);
    assert_eq!(out.status.code(), Some(1));
    let library =
        StatelessTemporalEngine::new("permit (principal, action, resource", SCHEMA, None, None)
            .expect_err("rejected")
            .to_string();
    assert_eq!(text(&out.stderr), format!("dogwood-server: {library}\n"));
}

#[test]
fn events_can_come_from_standard_input_as_a_json_array() {
    let f = Files::new("stdin", &[]);
    let array = format!(
        "[{}, {}]",
        event(T0, "Read", "response"),
        event(T0 + 2 * HOUR, "Export", "request")
    );
    let out = f.run_with_stdin(&["--events", "-"], Some(&array));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).starts_with("ALLOW\n"));
}

#[test]
fn no_state_directory_is_touched() {
    let f = Files::new("nodir", &[event(T0, "Export", "request")]);
    let dir: &Path = &f.path("never-created");
    let out = f.run(&["--dir", dir.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!dir.exists(), "decide-last must not create a store");
}
