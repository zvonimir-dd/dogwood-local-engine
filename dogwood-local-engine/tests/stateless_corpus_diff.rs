//! Differential test: `StatelessTemporalEngine::decide_last` against Dogwood's
//! reference interpreter over the whole passing temporal corpus.
//!
//! For every trace, the reference `Authorizer` (the oracle) replays the trace and
//! decides each decision point; for every prefix ending at a decision point, the
//! stateless engine — compiled once per case and reused across its traces and
//! prefixes — must reach the same decision, with the same determining rules (by
//! source index) and the same errors. A prefix ending at a history event must be
//! refused as not a decision kind.
//!
//! The corpus stamps events in whole seconds (strictly increasing integers); the
//! stateless engine, like the durable one, works in nanoseconds, so its events
//! are the same events scaled by 1e9, which preserves every window exactly.
//!
//! The stateless engine compiles a set exactly as `install` would, which
//! validates more than the oracle's plain lowering. A case it refuses must be
//! refused by `install` with the same message; such cases are counted, not
//! compared.
//!
//! Requires the `corpus` feature on `dogwood-language` (a dev-dependency feature).

use std::path::PathBuf;

use dogwood_language::corpus::{TemporalCase, TemporalCategory, temporal_cases};
use dogwood_language::{
    Authorizer, Event, LoweredPolicySet, PolicySchema, ServiceSchema, UNPINNED_EVENT_SCHEMA,
    parse_trace,
};
use dogwood_local_engine::{
    DurableConfig, DurableLog, DurableTemporalEngine, StatelessTemporalEngine,
};

const NANOS_PER_SECOND: i64 = 1_000_000_000;

fn event_schema(case: &TemporalCase) -> &str {
    case.event_schema_src
        .as_deref()
        .unwrap_or(UNPINNED_EVENT_SCHEMA)
}

fn oracle(case: &TemporalCase) -> Option<Authorizer> {
    let service = ServiceSchema::builder()
        .event_schema_str(event_schema(case))
        .build()
        .ok()?;
    let schema = PolicySchema::from_cedarschema_str(&case.schema_src).ok()?;
    let lowered = LoweredPolicySet::from_str(&case.policy_src, &service, &schema).ok()?;
    Some(Authorizer::new(lowered))
}

fn install_error(case: &TemporalCase) -> Option<String> {
    let mut engine = DurableTemporalEngine::open_with_log_config(
        DurableLog::ephemeral().expect("an in-memory log"),
        PathBuf::from("stateless-corpus"),
        DurableConfig::new(0),
    )
    .expect("opens");
    engine
        .install(
            &case.policy_src,
            &case.schema_src,
            Some(event_schema(case)),
            None,
        )
        .err()
        .map(|e| e.to_string())
}

fn scaled(event: &Event) -> Option<Event> {
    let ts = event.timestamp().checked_mul(NANOS_PER_SECOND)?;
    Some(event.clone().into_builder().timestamp(ts).build())
}

/// The source index a placeholder token (`SPref<n>`) names.
fn token_index(token: &str) -> usize {
    token
        .strip_prefix("SPref")
        .and_then(|n| n.parse().ok())
        .expect("a placeholder token")
}

#[derive(Default)]
struct Tally {
    cases: usize,
    rejected: usize,
    traces: usize,
    decisions: usize,
    history_refusals: usize,
    mismatches: Vec<String>,
}

fn diff_case(case: &TemporalCase) -> Tally {
    let mut t = Tally {
        cases: 1,
        ..Tally::default()
    };
    if oracle(case).is_none() {
        return t; // the oracle cannot lower it either; corpus_diff reports these
    }
    let mut stateless = match StatelessTemporalEngine::new(
        &case.policy_src,
        &case.schema_src,
        Some(event_schema(case)),
        None,
    ) {
        Ok(engine) => engine,
        Err(e) => {
            t.rejected += 1;
            match install_error(case) {
                Some(install) if install == e.to_string() => {}
                other => t.mismatches.push(format!(
                    "{}: compile rejected ({e}) but install gave {other:?}",
                    case.name
                )),
            }
            return t;
        }
    };

    for trace in &case.traces {
        let Ok(events) = parse_trace(&trace.trace_log) else {
            continue; // corpus_diff reports unparsable traces
        };
        let Some(scaled_events) = events.iter().map(scaled).collect::<Option<Vec<_>>>() else {
            t.mismatches.push(format!(
                "{}/trace_{}: timestamps overflow at 1e9",
                case.name, trace.index
            ));
            continue;
        };
        t.traces += 1;
        let mut reference = oracle(case).expect("lowered above");
        for (i, event) in events.iter().enumerate() {
            let want = reference.is_authorized(event);
            let got = stateless.decide_last(&scaled_events[..=i]);
            let at = format!("{}/trace_{} tp {i}", case.name, trace.index);
            match (want, got) {
                (Some(want), Ok(got)) => {
                    t.decisions += 1;
                    if want.decision() != got.response.decision() {
                        t.mismatches.push(format!(
                            "{at}: oracle {:?} vs stateless {:?}",
                            want.decision(),
                            got.response.decision()
                        ));
                        continue;
                    }
                    let mut want_rules: Vec<usize> =
                        want.diagnostics().reason().map(|r| r.rule_index).collect();
                    let mut got_rules: Vec<usize> = got
                        .response
                        .diagnostics()
                        .reason()
                        .map(|a| token_index(&a.token.to_string()))
                        .collect();
                    want_rules.sort_unstable();
                    got_rules.sort_unstable();
                    if want_rules != got_rules {
                        t.mismatches.push(format!(
                            "{at}: rules oracle {want_rules:?} vs stateless {got_rules:?}"
                        ));
                    }
                    let mut want_errors: Vec<&str> = want.diagnostics().errors().collect();
                    let mut got_errors: Vec<&str> = got.response.diagnostics().errors().collect();
                    want_errors.sort_unstable();
                    got_errors.sort_unstable();
                    if want_errors != got_errors {
                        t.mismatches.push(format!(
                            "{at}: errors oracle {want_errors:?} vs stateless {got_errors:?}"
                        ));
                    }
                }
                (None, Err(e)) if e.to_string().contains("not a decision kind") => {
                    t.history_refusals += 1
                }
                (want, got) => t.mismatches.push(format!(
                    "{at}: oracle {:?} vs stateless {:?}",
                    want.map(|r| r.decision()),
                    got.map(|d| d.response.decision())
                )),
            }
        }
    }
    t
}

/// `corpus_diff`'s deterministic parallel map: contiguous chunks, joined in order.
fn map_cases_parallel<T: Send>(
    cases: &[TemporalCase],
    f: impl Fn(&TemporalCase) -> T + Sync,
) -> Vec<T> {
    let nthreads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(cases.len().max(1));
    let chunk_size = cases.len().div_ceil(nthreads).max(1);
    let f = &f;
    std::thread::scope(|scope| {
        let handles: Vec<_> = cases
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(f).collect::<Vec<T>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker thread panicked"))
            .collect()
    })
}

#[test]
fn stateless_engine_matches_the_oracle_on_every_corpus_prefix() {
    let passing: Vec<TemporalCase> = temporal_cases()
        .into_iter()
        .filter(|c| c.category == TemporalCategory::Passing)
        .collect();
    assert!(
        !passing.is_empty(),
        "corpus feature must be enabled — no passing cases"
    );

    let mut total = Tally::default();
    for t in map_cases_parallel(&passing, diff_case) {
        total.cases += t.cases;
        total.rejected += t.rejected;
        total.traces += t.traces;
        total.decisions += t.decisions;
        total.history_refusals += t.history_refusals;
        total.mismatches.extend(t.mismatches);
    }
    eprintln!(
        "stateless corpus diff: {} cases ({} refused at compile, as by install), {} traces, \
         {} decisions compared, {} history prefixes refused",
        total.cases, total.rejected, total.traces, total.decisions, total.history_refusals
    );
    assert!(
        total.mismatches.is_empty(),
        "{} mismatch(es):\n{}",
        total.mismatches.len(),
        total
            .mismatches
            .iter()
            .take(60)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        total.decisions > 1000,
        "too few decisions compared: {}",
        total.decisions
    );
}
