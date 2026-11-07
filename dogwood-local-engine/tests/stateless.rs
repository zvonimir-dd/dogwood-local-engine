//! `StatelessTemporalEngine::decide_last` against the durable engine.
//!
//! The contract: for every prefix of a history, the stateless decision for the
//! prefix's last event is exactly what `submit` returned for that event on a
//! fresh `DurableTemporalEngine` that installed the same policy set and received
//! the same events at the same clock readings. "Exactly" means the decided
//! timestamp, allow/deny, the evaluation errors and the determining policies'
//! annotations (the tokens differ by design: the stateless ones are
//! placeholders). A history event (`Recorded`) corresponds to `BadEvent`, and a
//! submit error to a stateless error with the same message.
//!
//! The scripted histories mix actions, kinds and principals, tie timestamps and
//! straddle window edges, and include requests without a request context (an
//! evaluation error) and requests for an undeclared action (no decision). They
//! run under the default, pinned event schema (partitioned monitors), the
//! unpinned schema (global monitors), and with an aggregate rule. No temp files:
//! the durable side runs on an in-memory log.
//!
//! The history cache is held to the uncached engine: on every prefix of the same
//! histories, at several capacities, its decisions are identical, and its
//! counters show which calls replayed what.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use dogwood_language::{Event, EventBuilder, UNPINNED_EVENT_SCHEMA, Value};
use dogwood_local_engine::{
    Clock, Decided, DecisionResponse, DurableConfig, DurableError, DurableLog,
    DurableTemporalEngine, HistoryCacheStats, Outcome, StatelessTemporalEngine, Submitted,
    decide_last,
};

const SECOND: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * SECOND;
const T0: i64 = 1_700_000_000 * SECOND;

/// A clock a test drives by hand (as in tests/clock.rs).
#[derive(Clone)]
struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    fn new(nanos: i64) -> Self {
        ManualClock(Arc::new(AtomicI64::new(nanos)))
    }
    fn set(&self, nanos: i64) {
        self.0.store(nanos, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_nanos(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

const ACTION_SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Export appliesTo {
    principal: User, resource: Doc, context: { input: { doc: String } }
};
action Draft appliesTo {
    principal: User, resource: Doc,
    context: { input: { doc: String }, output?: { cents: Long } }
};
"#;

/// Plain, correlated and windowed rules, each annotated.
const POLICY: &str = r#"
@id("base")
@description("Allowed unless a rule forbids it.")
permit (principal, action, resource);

@id("no_secret")
@description("The secret document cannot be read.")
forbid (principal, action == Action::"Read", resource)
when { context.input.doc == "secret" };

@id("cooldown")
@description("No export within an hour of a read.")
forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };

@id("read_this_doc_first")
@description("Export only a document read in the last 24 hours.")
forbid (principal, action == Action::"Export", resource)
unless temporal { formerly within 24h Action::"Read"::response{ input.doc: context.input.doc } };
"#;

/// A rolling budget: the aggregate rule the "verdicts don't change state" premise matters most for.
const BUDGET: &str = r#"
@id("base")
permit (principal, action, resource);

@id("draft_budget")
@description("At most 3 dollars of drafts in any 10 minutes.")
forbid (principal, action == Action::"Draft", resource)
when temporal {
    (sum c for (c: Long), (t: Timepoint). where (
        formerly within 10m (Action::"Draft"::response{ output.cents: c } && tp(t))
    )) >= 300
};
"#;

/// One scripted event: built fresh for each side, so neither shares the other's builder.
#[derive(Clone, Debug)]
struct Spec {
    action: &'static str,
    kind: &'static str,
    who: &'static str,
    doc: &'static str,
    cents: Option<i64>,
    with_context: bool,
}

impl Spec {
    fn builder(&self) -> EventBuilder {
        let doc = Value::String(self.doc.to_string());
        let mut b = Event::builder(&format!("Action::{}", self.action), self.kind)
            .principal(&format!("User::\"{}\"", self.who))
            .resource("Doc::\"d1\"")
            .field("input", "doc", doc.clone());
        if self.with_context {
            b = b.request_context("input", "doc", doc);
        }
        if let Some(c) = self.cents {
            b = b.field("output", "cents", Value::Int(c));
        }
        b
    }
}

/// A deterministic LCG, so the scripts are reproducible without a dependency.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next() % items.len() as u64) as usize]
    }
}

/// `n` scripted (given timestamp, event) steps for the Read/Export policy.
fn script(seed: u64, n: usize) -> Vec<(i64, Spec)> {
    let mut rng = Lcg(seed);
    let gaps = [0, 1, SECOND, 20 * MINUTE, 61 * MINUTE];
    let mut ts = T0;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        ts += *rng.pick(&gaps);
        let roll = rng.next() % 100;
        let spec = Spec {
            action: if roll < 3 {
                "Nope"
            } else {
                rng.pick(&["Read", "Read", "Export"])
            },
            kind: rng.pick(&["request", "request", "response"]),
            who: rng.pick(&["alice", "bob", "carol"]),
            doc: rng.pick(&["d1", "d2", "secret"]),
            cents: None,
            with_context: roll >= 8,
        };
        out.push((ts, spec));
    }
    out
}

/// Drafts and their costs, for the budget rule.
fn budget_script(seed: u64, n: usize) -> Vec<(i64, Spec)> {
    let mut rng = Lcg(seed);
    let gaps = [0, SECOND, 2 * MINUTE, 6 * MINUTE];
    let mut ts = T0;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        ts += *rng.pick(&gaps);
        let response = i % 2 == 1;
        out.push((
            ts,
            Spec {
                action: "Draft",
                kind: if response { "response" } else { "request" },
                who: rng.pick(&["alice", "bob"]),
                doc: "d1",
                cents: response.then(|| *rng.pick(&[50, 75, 125])),
                with_context: true,
            },
        ));
    }
    out
}

fn durable(
    policy: &str,
    event_schema: Option<&str>,
    start: i64,
) -> (DurableTemporalEngine, ManualClock) {
    let clock = ManualClock::new(start - SECOND);
    let config = DurableConfig::new(0)
        .with_clock(Box::new(clock.clone()))
        .with_max_future_skew(Duration::from_secs(10 * 365 * 86_400));
    let log = DurableLog::ephemeral().expect("an in-memory log");
    let mut engine =
        DurableTemporalEngine::open_with_log_config(log, PathBuf::from("stateless-parity"), config)
            .expect("opens");
    engine
        .install(policy, ACTION_SCHEMA, event_schema, None)
        .expect("installs");
    (engine, clock)
}

/// A determining policy, compared by its annotations.
fn reasons(r: &DecisionResponse) -> Vec<BTreeMap<String, String>> {
    let mut v: Vec<_> = r
        .diagnostics()
        .reason()
        .map(|a| a.annotations.clone())
        .collect();
    v.sort();
    v
}

fn errors(r: &DecisionResponse) -> Vec<String> {
    r.diagnostics().errors().map(String::from).collect()
}

/// (decided ts, allowed, errors, (token, annotations) per determining policy).
type Normalized = (
    i64,
    bool,
    Vec<String>,
    Vec<(String, BTreeMap<String, String>)>,
);

/// A decision with its determining policies in a fixed order (their order is
/// unspecified, as from `submit`), tokens included.
fn normalized(d: &Decided) -> Normalized {
    let mut reasons: Vec<_> = d
        .response
        .diagnostics()
        .reason()
        .map(|a| (a.token.to_string(), a.annotations.clone()))
        .collect();
    reasons.sort();
    (d.ts, d.response.allowed(), errors(&d.response), reasons)
}

/// Assert one stateless result against what submit returned for the same event.
fn assert_same(
    i: usize,
    spec: &Spec,
    submitted: &Result<Submitted, DurableError>,
    stateless: &Result<Decided, DurableError>,
) {
    match (submitted, stateless) {
        (
            Ok(Submitted {
                ts,
                outcome: Outcome::Decision(r),
                ..
            }),
            Ok(d),
        ) => {
            assert_eq!(d.ts, *ts, "#{i} {spec:?}: decided at");
            assert_eq!(d.response.allowed(), r.allowed(), "#{i} {spec:?}: decision");
            assert_eq!(errors(&d.response), errors(r), "#{i} {spec:?}: errors");
            assert_eq!(
                reasons(&d.response),
                reasons(r),
                "#{i} {spec:?}: determining policies"
            );
        }
        (
            Ok(Submitted {
                outcome: Outcome::Recorded,
                ..
            }),
            Err(DurableError::BadEvent(m)),
        ) => {
            assert!(m.contains("not a decision kind"), "#{i} {spec:?}: {m}");
        }
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "#{i} {spec:?}: error"),
        (a, b) => panic!("#{i} {spec:?}: submit gave {a:?}, decide_last gave {b:?}"),
    }
}

/// Submit every step to a fresh durable engine; then, for every prefix, the
/// stateless decision equals submit's. Returns (decisions compared, denials).
fn assert_prefix_parity(
    policy: &str,
    event_schema: Option<&str>,
    steps: &[(i64, Spec)],
) -> (usize, usize) {
    let (mut durable, clock) = durable(policy, event_schema, steps[0].0);
    let mut stateless =
        StatelessTemporalEngine::new(policy, ACTION_SCHEMA, event_schema, None).expect("compiles");
    assert_eq!(stateless.status(), durable.status(), "status");

    let mut events = Vec::with_capacity(steps.len());
    let (mut decisions, mut denials) = (0, 0);
    for (i, (given, spec)) in steps.iter().enumerate() {
        clock.set(*given);
        let submitted = durable.submit(spec.builder());
        // The given timestamp, not the assigned one: decide_last must spread ties itself.
        events.push(spec.builder().timestamp(*given).build());
        let decided = stateless.decide_last(&events);
        assert_same(i, spec, &submitted, &decided);
        if let Ok(d) = &decided {
            decisions += 1;
            denials += usize::from(!d.response.allowed());
        }
    }
    (decisions, denials)
}

#[test]
fn every_prefix_matches_submit_under_the_pinned_schema() {
    for seed in 1..=8 {
        let steps = script(seed, 160);
        let (decisions, denials) = assert_prefix_parity(POLICY, None, &steps);
        assert!(
            decisions > 50 && denials > 5,
            "seed {seed}: {decisions} decisions, {denials} denials"
        );
    }
}

#[test]
fn partitioning_is_live_in_the_stateless_engine() {
    let steps = script(3, 60);
    let events: Vec<Event> = steps
        .iter()
        .map(|(ts, s)| s.builder().timestamp(*ts).build())
        .collect();
    let mut stateless = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    let last = events.iter().rposition(|e| e.kind() == "request").unwrap();
    stateless.decide_last(&events[..=last]).ok();
    assert!(
        stateless.status().partition_key.len() == 1,
        "{:?}",
        stateless.status()
    );
    assert!(
        stateless.temporal_shard_count() >= 2,
        "got {}",
        stateless.temporal_shard_count()
    );
}

#[test]
fn every_prefix_matches_submit_under_the_unpinned_schema() {
    for seed in 11..=16 {
        let steps = script(seed, 160);
        let (decisions, denials) =
            assert_prefix_parity(POLICY, Some(UNPINNED_EVENT_SCHEMA), &steps);
        assert!(
            decisions > 50 && denials > 5,
            "seed {seed}: {decisions} decisions, {denials} denials"
        );
    }
}

#[test]
fn every_prefix_matches_submit_with_an_aggregate_budget() {
    for (seed, schema) in [(21, None), (22, Some(UNPINNED_EVENT_SCHEMA)), (23, None)] {
        let steps = budget_script(seed, 200);
        let (decisions, denials) = assert_prefix_parity(BUDGET, schema, &steps);
        assert!(
            decisions == 100 && denials > 3,
            "seed {seed}: {decisions} decisions, {denials} denials"
        );
    }
}

#[test]
fn compiling_rejects_exactly_what_install_rejects() {
    let bad: [(&str, &str, Option<&str>, Option<&str>); 5] = [
        (
            "permit (principal, action, resource",
            ACTION_SCHEMA,
            None,
            None,
        ),
        (
            r#"forbid (principal, action == Action::"Nope", resource);"#,
            ACTION_SCHEMA,
            None,
            None,
        ),
        (
            POLICY,
            "entity User; action Read appliesTo { principal: User",
            None,
            None,
        ),
        (
            POLICY,
            ACTION_SCHEMA,
            Some("decision event <A>::request {"),
            None,
        ),
        (POLICY, ACTION_SCHEMA, None, Some("macro broken(")),
    ];
    for (policy, schema, events, macros) in bad {
        let mut d = DurableTemporalEngine::open_with_log_config(
            DurableLog::ephemeral().unwrap(),
            PathBuf::from("compile-parity"),
            DurableConfig::new(0),
        )
        .unwrap();
        let install = d
            .install(policy, schema, events, macros)
            .expect_err("install rejects");
        let compile = StatelessTemporalEngine::new(policy, schema, events, macros)
            .expect_err("compile rejects");
        assert_eq!(compile.to_string(), install.to_string());
    }
}

fn event(action: &'static str, kind: &'static str, who: &'static str, ts: i64) -> Event {
    let spec = Spec {
        action,
        kind,
        who,
        doc: "d1",
        cents: None,
        with_context: kind == "request",
    };
    spec.builder().timestamp(ts).build()
}

fn read(ts: i64, kind: &'static str, who: &'static str) -> Event {
    event("Read", kind, who, ts)
}

fn export(ts: i64, who: &'static str) -> Event {
    event("Export", "request", who, ts)
}

#[test]
fn bad_histories_are_refused_and_the_engine_stays_usable() {
    let mut e = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    let msg = |r: Result<Decided, DurableError>| match r {
        Err(DurableError::BadEvent(m)) => m,
        other => panic!("expected BadEvent, got {other:?}"),
    };
    assert!(msg(e.decide_last(&[])).contains("history is empty"));
    assert!(msg(e.decide_last(&[read(T0, "response", "alice")])).contains("not a decision kind"));
    let decreasing = [
        read(T0 + 5 * SECOND, "response", "alice"),
        export(T0, "alice"),
    ];
    assert!(msg(e.decide_last(&decreasing)).contains("in time order"));
    let overflow = [
        read(i64::MAX, "response", "alice"),
        export(i64::MAX, "alice"),
    ];
    assert!(msg(e.decide_last(&overflow)).contains("cannot be stamped"));
    // still usable, and right
    let ok = e
        .decide_last(&[
            read(T0, "response", "alice"),
            export(T0 + 2 * 3600 * SECOND, "alice"),
        ])
        .unwrap();
    assert!(ok.response.allowed(), "{ok:?}");
}

#[test]
fn equal_timestamps_are_spread_like_submit_spreads_them() {
    let history = [read(T0, "response", "alice"), export(T0, "alice")];
    let d = decide_last(POLICY, ACTION_SCHEMA, None, None, &history).unwrap();
    assert_eq!(d.ts, T0 + 1);
    assert!(!d.response.allowed(), "the read is in the window");
}

#[test]
fn no_state_survives_a_call() {
    let mut e = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    let armed = [
        read(T0, "response", "alice"),
        read(T0, "response", "bob"),
        export(T0 + MINUTE, "alice"),
    ];
    assert!(
        !e.decide_last(&armed).unwrap().response.allowed(),
        "cooldown fires"
    );
    assert!(e.temporal_shard_count() >= 2);
    // The same export with no read before it: denied only by read_this_doc_first,
    // as a fresh engine decides it, with only carol's shards alive.
    let unarmed = [read(T0, "request", "carol"), export(T0 + MINUTE, "carol")];
    let reused = e.decide_last(&unarmed).unwrap();
    let mut fresh_engine = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    let fresh = fresh_engine.decide_last(&unarmed).unwrap();
    assert_eq!(normalized(&reused), normalized(&fresh));
    let ids: Vec<_> = reused
        .response
        .diagnostics()
        .reason()
        .filter_map(|a| a.annotation_id())
        .collect();
    assert_eq!(ids, ["read_this_doc_first"]);
    assert_eq!(
        e.temporal_shard_count(),
        fresh_engine.temporal_shard_count()
    );
}

#[test]
fn one_engine_reused_equals_a_fresh_engine_per_history() {
    let steps = script(42, 120);
    let events: Vec<Event> = steps
        .iter()
        .map(|(ts, s)| s.builder().timestamp(*ts).build())
        .collect();
    let mut reused = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    for i in 0..events.len() {
        let a = reused.decide_last(&events[..=i]);
        let b = decide_last(POLICY, ACTION_SCHEMA, None, None, &events[..=i]);
        match (a, b) {
            (Ok(a), Ok(b)) => assert_eq!(normalized(&a), normalized(&b), "#{i}"),
            (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "#{i}"),
            (a, b) => panic!("#{i}: reused {a:?}, fresh {b:?}"),
        }
    }
}

#[test]
fn placeholder_tokens_name_the_policies_in_order() {
    let e = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    let tokens: Vec<String> = e.list().iter().map(|p| p.token.to_string()).collect();
    assert_eq!(tokens, ["SPref0", "SPref1", "SPref2", "SPref3"]);
}

#[test]
fn the_engine_is_send() {
    fn send<T: Send>() {}
    send::<StatelessTemporalEngine>();
}

// ---- The history cache ------------------------------------------------------

fn events_of(steps: &[(i64, Spec)]) -> Vec<Event> {
    steps
        .iter()
        .map(|(ts, s)| s.builder().timestamp(*ts).build())
        .collect()
}

fn assert_same_result(
    what: &str,
    plain: &Result<Decided, DurableError>,
    cached: &Result<Decided, DurableError>,
) {
    match (plain, cached) {
        (Ok(a), Ok(b)) => assert_eq!(normalized(a), normalized(b), "{what}"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "{what}"),
        (a, b) => panic!("{what}: uncached {a:?}, cached {b:?}"),
    }
}

/// What one call did, from two readings of the counters.
fn delta(before: HistoryCacheStats, after: HistoryCacheStats) -> HistoryCacheStats {
    HistoryCacheStats {
        calls: after.calls - before.calls,
        exact_hits: after.exact_hits - before.exact_hits,
        prefix_hits: after.prefix_hits - before.prefix_hits,
        misses: after.misses - before.misses,
        reused_events: after.reused_events - before.reused_events,
        replayed_events: after.replayed_events - before.replayed_events,
    }
}

fn miss(replayed: u64) -> HistoryCacheStats {
    HistoryCacheStats {
        calls: 1,
        misses: 1,
        replayed_events: replayed,
        ..HistoryCacheStats::default()
    }
}

fn prefix_hit(reused: u64, replayed: u64) -> HistoryCacheStats {
    HistoryCacheStats {
        calls: 1,
        prefix_hits: 1,
        reused_events: reused,
        replayed_events: replayed,
        ..HistoryCacheStats::default()
    }
}

fn exact_hit(reused: u64) -> HistoryCacheStats {
    HistoryCacheStats {
        calls: 1,
        exact_hits: 1,
        reused_events: reused,
        ..HistoryCacheStats::default()
    }
}

/// Decide every prefix with the cache at `capacity` and without it: identical
/// results, and each call after the first decision replays only the events since
/// the previous one. Returns the counters.
fn assert_cache_transparent(
    policy: &str,
    event_schema: Option<&str>,
    steps: &[(i64, Spec)],
    capacity: usize,
) -> HistoryCacheStats {
    let events = events_of(steps);
    let mut plain =
        StatelessTemporalEngine::new(policy, ACTION_SCHEMA, event_schema, None).unwrap();
    let mut cached = StatelessTemporalEngine::new(policy, ACTION_SCHEMA, event_schema, None)
        .unwrap()
        .with_history_cache(capacity);
    // The end of the history the cache holds, if any.
    let mut held: Option<usize> = None;
    for i in 0..events.len() {
        let before = cached.history_cache_stats();
        let a = plain.decide_last(&events[..=i]);
        let b = cached.decide_last(&events[..=i]);
        let what = format!("capacity {capacity}, #{i} {:?}", steps[i].1);
        assert_same_result(&what, &a, &b);
        let did = delta(before, cached.history_cache_stats());
        match &b {
            Ok(_) => {
                let expected = match held {
                    Some(h) => prefix_hit(h as u64 + 1, (i - h) as u64),
                    None => miss(i as u64 + 1),
                };
                assert_eq!(did, expected, "{what}");
                held = Some(i);
            }
            // Refused before the cache is consulted.
            Err(DurableError::BadEvent(m)) if m.contains("not a decision kind") => {
                assert_eq!(
                    did,
                    HistoryCacheStats {
                        calls: 1,
                        ..HistoryCacheStats::default()
                    },
                    "{what}"
                );
            }
            // A failed decision (an undeclared action) drops the history.
            Err(_) => held = None,
        }
    }
    cached.history_cache_stats()
}

/// (policy, event schema, scripted steps).
type Case = (&'static str, Option<&'static str>, Vec<(i64, Spec)>);

#[test]
fn the_history_cache_changes_no_decision() {
    let cases: Vec<Case> = vec![
        (POLICY, None, script(1, 160)),
        (POLICY, None, script(2, 160)),
        (POLICY, Some(UNPINNED_EVENT_SCHEMA), script(11, 160)),
        (POLICY, Some(UNPINNED_EVENT_SCHEMA), script(12, 160)),
        (BUDGET, None, budget_script(21, 200)),
        (BUDGET, Some(UNPINNED_EVENT_SCHEMA), budget_script(22, 200)),
    ];
    for (policy, schema, steps) in &cases {
        for capacity in [1, 2, 16] {
            let stats = assert_cache_transparent(policy, *schema, steps, capacity);
            assert!(
                stats.prefix_hits > 40 && stats.prefix_hits > 5 * stats.misses,
                "{schema:?}, capacity {capacity}: {stats:?}"
            );
        }
    }
}

/// `n` steps of a script without undeclared actions, `offset` nanoseconds later,
/// so histories built from different offsets never share a first event.
fn clean_script(seed: u64, n: usize, offset: i64) -> Vec<Event> {
    script(seed, n)
        .into_iter()
        .filter(|(_, s)| s.action != "Nope")
        .map(|(ts, s)| s.builder().timestamp(ts + offset).build())
        .collect()
}

/// The prefix ends at which `events` has a decision (a request).
fn decision_ends(events: &[Event]) -> Vec<usize> {
    (0..events.len())
        .filter(|&i| events[i].kind() == "request")
        .collect()
}

#[test]
fn interleaved_histories_hit_when_the_cache_holds_them_all() {
    let lines: Vec<Vec<Event>> = (0..3)
        .map(|h| clean_script(30 + h as u64, 120, h))
        .collect();
    let ends: Vec<Vec<usize>> = lines.iter().map(|l| decision_ends(l)).collect();
    let rounds = ends.iter().map(Vec::len).min().unwrap();
    assert!(rounds > 30, "{rounds}");

    let mut plain = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    let mut roomy = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None)
        .unwrap()
        .with_history_cache(3);
    let mut cramped = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None)
        .unwrap()
        .with_history_cache(1);
    for round in 0..rounds {
        for (h, line) in lines.iter().enumerate() {
            let history = &line[..=ends[h][round]];
            let expected = plain.decide_last(history);
            let what = format!("round {round}, history {h}");
            assert_same_result(&what, &expected, &roomy.decide_last(history));
            assert_same_result(&what, &expected, &cramped.decide_last(history));
        }
    }
    let calls = 3 * rounds as u64;
    let roomy = roomy.history_cache_stats();
    assert_eq!(
        (roomy.misses, roomy.prefix_hits),
        (3, calls - 3),
        "{roomy:?}"
    );
    let cramped = cramped.history_cache_stats();
    assert_eq!(
        (cramped.misses, cramped.prefix_hits),
        (calls, 0),
        "{cramped:?}"
    );
}

#[test]
fn a_history_that_differs_anywhere_is_a_miss() {
    let base = clean_script(40, 60, 0);
    let ends = decision_ends(&base);
    let end = ends[ends.len() - 1];
    let history = &base[..=end];
    let mut plain = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    let mut cached = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None)
        .unwrap()
        .with_history_cache(16);
    cached.decide_last(history).unwrap();

    let mid = end / 2;
    // One event changed in the middle: another principal.
    let mut changed_event = history.to_vec();
    let who = if changed_event[mid]
        .principal()
        .is_some_and(|p| p.contains("alice"))
    {
        "bob"
    } else {
        "alice"
    };
    changed_event[mid] = changed_event[mid]
        .clone()
        .into_builder()
        .principal(&format!("User::\"{who}\""))
        .build();
    // One timestamp moved a nanosecond (still in order).
    let mut changed_time = history.to_vec();
    let mut moved = mid;
    while history[moved + 1].timestamp() == history[moved].timestamp() {
        moved += 1;
    }
    changed_time[moved] = history[moved]
        .clone()
        .into_builder()
        .timestamp(history[moved].timestamp() + 1)
        .build();
    // The same change, with the history extended past the cached one.
    let mut changed_and_longer = changed_event.clone();
    changed_and_longer.push(export(history[end].timestamp() + SECOND, "alice"));

    // Each variant is cached once decided, so the longer one goes first: the
    // others would be prefixes of it, not extensions.
    for (what, variant) in [
        ("changed and longer", &changed_and_longer),
        ("an event changed", &changed_event),
        ("a timestamp changed", &changed_time),
    ] {
        assert_ne!(variant.as_slice(), history, "{what}");
        let before = cached.history_cache_stats();
        let got = cached.decide_last(variant);
        assert_same_result(what, &plain.decide_last(variant), &got);
        assert_eq!(
            delta(before, cached.history_cache_stats()),
            miss(variant.len() as u64),
            "{what}"
        );
    }

    // Another bundle's engine has its own cache.
    let mut other = StatelessTemporalEngine::new(BUDGET, ACTION_SCHEMA, None, None)
        .unwrap()
        .with_history_cache(16);
    let _ = other.decide_last(history);
    assert_eq!(other.history_cache_stats().misses, 1);
}

#[test]
fn an_earlier_point_is_a_miss_and_a_repeat_is_an_exact_hit() {
    let line = clean_script(50, 80, 0);
    let ends = decision_ends(&line);
    let (a, b, c) = (ends[5], ends[10], ends[15]);
    assert!(a < b && b < c);
    let mut plain = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None).unwrap();
    for capacity in [1, 2] {
        let mut e = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None)
            .unwrap()
            .with_history_cache(capacity);
        let mut call = |end: usize, expected: HistoryCacheStats| {
            let before = e.history_cache_stats();
            let got = e.decide_last(&line[..=end]).unwrap();
            let what = format!("capacity {capacity}, ..={end}");
            assert_same_result(&what, &plain.decide_last(&line[..=end]), &Ok(got.clone()));
            assert_eq!(delta(before, e.history_cache_stats()), expected, "{what}");
            got
        };
        call(a, miss(a as u64 + 1));
        let first_c = call(c, prefix_hit(a as u64 + 1, (c - a) as u64));
        // The cache holds ..=c only: ..=b is an earlier point of it.
        call(b, miss(b as u64 + 1));
        let again = if capacity == 1 {
            // ..=b displaced ..=c, and ..=c extends it.
            call(c, prefix_hit(b as u64 + 1, (c - b) as u64))
        } else {
            call(c, exact_hit(c as u64 + 1))
        };
        assert_eq!(again, first_c, "capacity {capacity}: identical decision");
        // An immediate repeat is always exact, Decided and all.
        assert_eq!(call(c, exact_hit(c as u64 + 1)), first_c);
    }
}

#[test]
fn the_least_recently_used_history_is_evicted_first_and_clear_empties_the_cache() {
    let lines: Vec<Vec<Event>> = (0..3).map(|h| clean_script(60 + h as u64, 80, h)).collect();
    let ends: Vec<Vec<usize>> = lines.iter().map(|l| decision_ends(l)).collect();
    let mut e = StatelessTemporalEngine::new(POLICY, ACTION_SCHEMA, None, None)
        .unwrap()
        .with_history_cache(2);
    let call = |e: &mut StatelessTemporalEngine, h: usize, round: usize| {
        let before = e.history_cache_stats();
        e.decide_last(&lines[h][..=ends[h][round]]).unwrap();
        let did = delta(before, e.history_cache_stats());
        (did.misses, did.prefix_hits)
    };
    assert_eq!(call(&mut e, 0, 0), (1, 0)); // A
    assert_eq!(call(&mut e, 1, 0), (1, 0)); // B
    assert_eq!(call(&mut e, 0, 1), (0, 1)); // A again: B is now the least recent
    assert_eq!(call(&mut e, 2, 0), (1, 0)); // C evicts B
    assert_eq!(call(&mut e, 0, 2), (0, 1), "A was kept");
    assert_eq!(call(&mut e, 2, 1), (0, 1), "C was kept");
    assert_eq!(call(&mut e, 1, 1), (1, 0), "B was evicted");

    e.clear().unwrap();
    assert_eq!(call(&mut e, 0, 3), (1, 0), "cleared");
    assert_eq!(call(&mut e, 0, 4), (0, 1), "and caching again");
    // Turning the cache off drops it, and calls are no longer counted.
    let mut e = e.with_history_cache(0);
    let before = e.history_cache_stats();
    e.decide_last(&lines[0][..=ends[0][5]]).unwrap();
    assert_eq!(e.history_cache_stats(), before);
}
