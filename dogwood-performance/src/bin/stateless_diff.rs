//! Differential test and latency harness for stateless decisions:
//! [`StatelessTemporalEngine::decide_last`] against the durable engine's
//! incremental `submit`, over a corpus of real trajectories and over synthetic
//! histories.
//!
//! # What it checks
//!
//! For each trajectory, a fresh [`DurableTemporalEngine`] (the default, stateful
//! engine; in-memory log, a clock set from each event's timestamp) installs the
//! trajectory's policy set and receives every event in order. Then, for every
//! selected prefix, the stateless engine — compiled once per policy set and
//! reused across that set's trajectories — decides the prefix's last event, and
//! the two must agree exactly: the decided timestamp, allow/deny, the
//! evaluation errors, and the determining policies (by position in the set). A
//! prefix ending at a history event must be refused as not a decision kind, and
//! a set the stateless engine refuses to compile must be refused by `install`
//! with the same message. Any disagreement is a mismatch, and the process exits
//! non-zero.
//!
//! # What it measures
//!
//! After the differential pass (parallel, untimed), a single-threaded latency
//! pass over a sample of each source: compile time per policy set, the durable
//! engine's per-decision `submit` latency (in memory, and on disk with
//! `--durable-dir`, which adds the fsync), the stateless per-call latency by
//! history length, and per trajectory the cost of deciding every request live
//! each way: incremental submits vs one stateless call per decision.
//!
//! # Inputs
//!
//! `--corpus DIR` reads a corpus: `manifest.jsonl` (one `{"id", "source",
//! "bundle", "path", …}` per trajectory), `bundles/<name>/{policy.dw,
//! action.cedarschema[, event.dwschema]}`, and one history file per trajectory
//! (`dogwood-server decide-last`'s `--events` format: JSON Lines of `{"ts":
//! <epoch ns>, "event": <wire event>}`). `--synthetic` adds the workload
//! generator's histories (`workload::event_stream`, timestamps scaled to
//! nanoseconds) at several sizes and policy counts, pinned and unpinned, plus a
//! seeded mixed history per configuration with tied timestamps and window edges.
//!
//! # Several sessions at once
//!
//! A real trajectory is one conversation, so it exercises one principal's
//! history at a time. `--merge 2,5,10` adds merged trajectories: `K`
//! consecutive corpus trajectories of the same source and policy set,
//! interleaved as if their conversations ran at once (each shifted to start at
//! the same instant, keeping its own gaps). Each merged trajectory is checked
//! like any other, stateless against stateful on every prefix, and also for
//! **isolation**: every member replayed alone, at the timestamps it had in the
//! merged history, must reach exactly the outcomes it reached there. Under a
//! principal pin, the members' events must be invisible to each other. Groups
//! whose members share a principal are counted and not checked for isolation.
//!
//! # The history cache
//!
//! `--history-cache N` gives the differential pass's stateless engines a cache
//! of `N` histories ([`StatelessTemporalEngine::with_history_cache`]). Prefixes
//! are decided in increasing order, so nearly every call extends the history
//! the call before it decided: the cached path is the one compared. The report
//! counts hits and misses, and the latency pass times a cached engine beside
//! the uncached one on the same prefixes.
//!
//! # Usage
//!
//! ```text
//! cargo run --release -p dogwood-performance --bin stateless_diff -- \
//!     [--corpus DIR] [--synthetic] [--merge K,…] [--prefixes all|<N>] [--threads <K>] \
//!     [--history-cache <N>] [--latency-trajectories <N>] [--durable-dir <DIR>] \
//!     [--report <FILE>]
//! ```
//!
//! `--prefixes`: `all` compares every prefix of every trajectory; a number `N`
//! (default 200) compares every prefix of trajectories up to 2,000 events and,
//! for longer ones, the last prefix, every (n/N)-th and N seeded-random ones.

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dogwood_language::{Event, UNPINNED_EVENT_SCHEMA};
use dogwood_local_engine::{
    Clock, Decided, DurableConfig, DurableError, DurableLog, DurableTemporalEngine,
    HistoryCacheStats, Outcome, StatelessTemporalEngine, Submitted,
};
use dogwood_performance::driver::to_event as gen_to_event;
use dogwood_performance::workload::{ACTION_SCHEMA, GenEvent, Pinning, event_stream, policy_set};
use dogwood_server::codec::to_event;
use dogwood_server::history::parse_history;
use serde_json::{Value, json};

const SECOND: i64 = 1_000_000_000;
const T0: i64 = 1_700_000_000 * SECOND;
/// Trajectories up to this many events always have every prefix compared.
const ALL_PREFIXES_UP_TO: usize = 2_000;

// ─── Inputs ──────────────────────────────────────────────────────────

struct Bundle {
    name: String,
    policy: String,
    action_schema: String,
    event_schema: Option<String>,
}

struct Trajectory {
    id: String,
    source: String,
    bundle: usize,
    events: Vec<Event>,
    /// For a merged trajectory: each original trajectory and the positions of
    /// its events in `events`. Empty otherwise.
    members: Vec<Member>,
}

struct Member {
    id: String,
    indices: Vec<usize>,
}

struct Config {
    corpus: Option<PathBuf>,
    synthetic: bool,
    prefixes: Option<usize>, // None = all
    threads: usize,
    latency_trajectories: usize,
    durable_dir: Option<PathBuf>,
    report: Option<PathBuf>,
    /// Group sizes for merged corpus trajectories (`--merge 2,5,10`).
    merge: Vec<usize>,
    /// History cache capacity for the stateless engines (`--history-cache N`; 0 = off).
    history_cache: usize,
}

impl Config {
    fn from_args() -> Self {
        let mut c = Config {
            corpus: None,
            synthetic: false,
            prefixes: Some(200),
            threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            latency_trajectories: 100,
            durable_dir: None,
            report: None,
            merge: Vec::new(),
            history_cache: 0,
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        let value = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i)
                .cloned()
                .unwrap_or_else(|| usage(&format!("{} needs a value", args[*i - 1])))
        };
        while i < args.len() {
            match args[i].as_str() {
                "--corpus" => c.corpus = Some(PathBuf::from(value(&mut i))),
                "--synthetic" => c.synthetic = true,
                "--prefixes" => {
                    let v = value(&mut i);
                    c.prefixes = if v == "all" {
                        None
                    } else {
                        Some(v.parse().unwrap_or_else(|_| usage("--prefixes all|<N>")))
                    };
                }
                "--threads" => {
                    c.threads = value(&mut i)
                        .parse()
                        .unwrap_or_else(|_| usage("--threads <K>"))
                }
                "--latency-trajectories" => {
                    c.latency_trajectories = value(&mut i)
                        .parse()
                        .unwrap_or_else(|_| usage("--latency-trajectories <N>"))
                }
                "--history-cache" => {
                    c.history_cache = value(&mut i)
                        .parse()
                        .unwrap_or_else(|_| usage("--history-cache <N>"))
                }
                "--durable-dir" => c.durable_dir = Some(PathBuf::from(value(&mut i))),
                "--report" => c.report = Some(PathBuf::from(value(&mut i))),
                "--merge" => {
                    c.merge = value(&mut i)
                        .split(',')
                        .map(|k| match k.trim().parse() {
                            Ok(k) if k >= 2 => k,
                            _ => usage("--merge <K>[,<K>…] with every K at least 2"),
                        })
                        .collect()
                }
                other => usage(&format!("unknown argument {other}")),
            }
            i += 1;
        }
        if c.corpus.is_none() && !c.synthetic {
            usage("give --corpus DIR, --synthetic, or both");
        }
        if !c.merge.is_empty() && c.corpus.is_none() {
            usage("--merge needs --corpus");
        }
        c
    }
}

fn usage(problem: &str) -> ! {
    eprintln!(
        "stateless_diff: {problem}\nusage: stateless_diff [--corpus DIR] [--synthetic] [--merge K,…] \
         [--prefixes all|N] [--threads K] [--history-cache N] [--latency-trajectories N] \
         [--durable-dir DIR] [--report FILE]"
    );
    std::process::exit(2)
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn load_corpus(dir: &Path, bundles: &mut Vec<Bundle>, out: &mut Vec<Trajectory>) {
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for line in read(&dir.join("manifest.jsonl"))
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        let m: Value = serde_json::from_str(line).expect("manifest line is JSON");
        let name = m["bundle"].as_str().expect("bundle").to_string();
        let bundle = *by_name.entry(name.clone()).or_insert_with(|| {
            let b = dir.join("bundles").join(&name);
            let event_schema = b.join("event.dwschema");
            bundles.push(Bundle {
                name: name.clone(),
                policy: read(&b.join("policy.dw")),
                action_schema: read(&b.join("action.cedarschema")),
                event_schema: event_schema.exists().then(|| read(&event_schema)),
            });
            bundles.len() - 1
        });
        let path = dir.join(m["path"].as_str().expect("path"));
        let history =
            parse_history(&read(&path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        out.push(Trajectory {
            id: m["id"].as_str().expect("id").to_string(),
            source: m["source"].as_str().expect("source").to_string(),
            bundle,
            events: history.iter().map(|t| to_event(&t.event, t.ts)).collect(),
            members: Vec::new(),
        });
    }
}

/// The workload generator's history, stamped in nanoseconds from `T0`.
fn workload_history(n: usize) -> Vec<Event> {
    event_stream(n, 10, 49, 5)
        .iter()
        .map(|e| {
            let event = gen_to_event(e);
            event
                .clone()
                .into_builder()
                .timestamp(T0 + e.ts * SECOND)
                .build()
        })
        .collect()
}

/// A seeded mixed history over the workload schema: ties, nanosecond steps and
/// window edges around the rules' one hour, logins by the blocked user.
fn mixed_history(n: usize, seed: u64) -> Vec<Event> {
    let mut state = seed;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state >> 33
    };
    let gaps = [0, 1, SECOND, 59 * 60 * SECOND, 61 * 60 * SECOND];
    let mut ts = T0;
    (0..n)
        .map(|_| {
            ts += gaps[(next() % gaps.len() as u64) as usize];
            let login = next() % 3 == 0;
            let user = if login && next() % 2 == 0 {
                "blocked0".to_string()
            } else {
                format!("u{}", next() % 4)
            };
            let g = GenEvent {
                action: if login { "Login" } else { "Read" },
                ts: 0,
                user,
                server: format!("s{}", next() % 3),
                session: format!("sess{}", next() % 3),
                decides: !login,
            };
            gen_to_event(&g).into_builder().timestamp(ts).build()
        })
        .collect()
}

fn add_synthetic(bundles: &mut Vec<Bundle>, out: &mut Vec<Trajectory>) {
    let grid: &[(usize, &[usize])] = &[
        (10, &[100, 1_000, 5_000]),
        (100, &[100, 1_000, 5_000]),
        (1_000, &[100, 1_000]),
    ];
    for &(policies, sizes) in grid {
        for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
            bundles.push(Bundle {
                name: format!("workload-{policies}p-{}", pinning.label()),
                policy: policy_set(policies),
                action_schema: ACTION_SCHEMA.to_string(),
                event_schema: Some(pinning.event_schema().to_string()),
            });
            let bundle = bundles.len() - 1;
            let source = format!("synthetic-{}", pinning.label());
            for &n in sizes {
                out.push(Trajectory {
                    id: format!("stream-{policies}p-{n}"),
                    source: source.clone(),
                    bundle,
                    events: workload_history(n),
                    members: Vec::new(),
                });
            }
            out.push(Trajectory {
                id: format!("mixed-{policies}p-300"),
                source: source.clone(),
                bundle,
                events: mixed_history(300, policies as u64 * 31 + pinning.label().len() as u64),
                members: Vec::new(),
            });
        }
    }
    // The global, unpinned schema with the default name, so the corpus and the
    // synthetic runs both cover a store with no pins at all.
    debug_assert_eq!(Pinning::Unpinned.event_schema(), UNPINNED_EVENT_SCHEMA);
}

/// Interleave several trajectories of one policy set into one history, as if
/// their conversations ran at the same time: member `j` is shifted to start at
/// `T0 + j µs` (keeping all of its own gaps), the events are merged by time, and
/// each gets the timestamp the durable engine's clamp would give it
/// (`max(ts, previous + 1)`). Members keep their events at those timestamps, so a
/// member replayed alone sees exactly the times it saw in the merged history.
fn merge_group(source: &str, k: usize, n: usize, chunk: &[&Trajectory]) -> Trajectory {
    let mut order: Vec<(i64, usize, usize)> = Vec::new();
    for (j, t) in chunk.iter().enumerate() {
        let base = t.events[0].timestamp();
        for (i, e) in t.events.iter().enumerate() {
            order.push((T0 + (e.timestamp() - base) + j as i64 * 1_000, j, i));
        }
    }
    order.sort_unstable();
    let mut events = Vec::with_capacity(order.len());
    let mut members: Vec<Member> = chunk
        .iter()
        .map(|t| Member {
            id: t.id.clone(),
            indices: Vec::new(),
        })
        .collect();
    let mut previous: Option<i64> = None;
    for (position, (ts, j, i)) in order.into_iter().enumerate() {
        let effective = match previous {
            Some(p) if ts <= p => p + 1,
            _ => ts,
        };
        previous = Some(effective);
        events.push(
            chunk[j].events[i]
                .clone()
                .into_builder()
                .timestamp(effective)
                .build(),
        );
        members[j].indices.push(position);
    }
    Trajectory {
        id: format!("merge{k}-{n:03}"),
        source: format!("{source}×{k}"),
        bundle: chunk[0].bundle,
        events,
        members,
    }
}

/// For each group size `k`, merged trajectories made of `k` consecutive corpus
/// trajectories that share a source and a policy set.
fn add_merged(sizes: &[usize], out: &mut Vec<Trajectory>) {
    let mut groups: Vec<((String, usize), Vec<usize>)> = Vec::new();
    for (i, t) in out.iter().enumerate() {
        if t.events.is_empty() {
            continue;
        }
        let key = (t.source.clone(), t.bundle);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => members.push(i),
            None => groups.push((key, vec![i])),
        }
    }
    let mut merged = Vec::new();
    for &k in sizes {
        let mut counters: HashMap<String, usize> = HashMap::new();
        for ((source, _), members) in &groups {
            for chunk in members.chunks(k).filter(|c| c.len() >= 2) {
                let n = counters.entry(source.clone()).or_insert(0);
                let refs: Vec<&Trajectory> = chunk.iter().map(|&i| &out[i]).collect();
                merged.push(merge_group(source, k, *n, &refs));
                *n += 1;
            }
        }
    }
    out.extend(merged);
}

// ─── Running the two engines ─────────────────────────────────────────

#[derive(Clone)]
struct ManualClock(Arc<AtomicI64>);

impl Clock for ManualClock {
    fn now_nanos(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A durable engine with `bundle` installed a second before `first_ts`:
/// in memory, or as a file under `dir`. `Err` is install's rejection message.
fn durable(
    bundle: &Bundle,
    first_ts: i64,
    dir: Option<&Path>,
    tag: &str,
) -> Result<(DurableTemporalEngine, ManualClock, Option<PathBuf>), String> {
    let clock = ManualClock(Arc::new(AtomicI64::new(first_ts - SECOND)));
    let config = DurableConfig::new(0)
        .with_clock(Box::new(clock.clone()))
        .with_max_future_skew(Duration::from_secs(10 * 365 * 86_400));
    let (mut engine, path) = match dir {
        None => {
            let log = DurableLog::ephemeral().map_err(|e| format!("open: {e}"))?;
            (
                DurableTemporalEngine::open_with_log_config(log, PathBuf::from(tag), config)
                    .map_err(|e| format!("open: {e}"))?,
                None,
            )
        }
        Some(dir) => {
            let path = dir.join(format!("stateless-diff-{}-{tag}.redb", std::process::id()));
            let _ = std::fs::remove_file(&path);
            (
                DurableTemporalEngine::open_with_config(&path, config)
                    .map_err(|e| format!("open: {e}"))?,
                Some(path),
            )
        }
    };
    engine
        .install(
            &bundle.policy,
            &bundle.action_schema,
            bundle.event_schema.as_deref(),
            None,
        )
        .map_err(|e| e.to_string())?;
    Ok((engine, clock, path))
}

fn compile(bundle: &Bundle, history_cache: usize) -> Result<StatelessTemporalEngine, String> {
    StatelessTemporalEngine::new(
        &bundle.policy,
        &bundle.action_schema,
        bundle.event_schema.as_deref(),
        None,
    )
    .map(|e| e.with_history_cache(history_cache))
    .map_err(|e| e.to_string())
}

/// The comparable form of one outcome: (decided ts, allowed, errors, policy positions).
type Verdict = (i64, bool, Vec<String>, Vec<usize>);

fn durable_verdict(s: &Submitted, positions: &HashMap<String, usize>) -> Option<Verdict> {
    let Outcome::Decision(r) = &s.outcome else {
        return None;
    };
    let mut errors: Vec<String> = r.diagnostics().errors().map(String::from).collect();
    let mut rules: Vec<usize> = r
        .diagnostics()
        .reason()
        .map(|a| positions[&a.token.to_string()])
        .collect();
    errors.sort();
    rules.sort_unstable();
    Some((s.ts, r.allowed(), errors, rules))
}

fn stateless_verdict(d: &Decided) -> Verdict {
    let mut errors: Vec<String> = d
        .response
        .diagnostics()
        .errors()
        .map(String::from)
        .collect();
    let mut rules: Vec<usize> = d
        .response
        .diagnostics()
        .reason()
        .map(|a| {
            a.token
                .to_string()
                .strip_prefix("SPref")
                .and_then(|n| n.parse().ok())
                .expect("placeholder token")
        })
        .collect();
    errors.sort();
    rules.sort_unstable();
    (d.ts, d.response.allowed(), errors, rules)
}

/// `None` when they agree; otherwise what differed.
fn compare(
    submitted: &Result<Submitted, DurableError>,
    positions: &HashMap<String, usize>,
    decided: &Result<Decided, DurableError>,
) -> Option<String> {
    match (submitted, decided) {
        (Ok(s), Ok(d)) => match durable_verdict(s, positions) {
            Some(want) => {
                let got = stateless_verdict(d);
                (want != got).then(|| format!("submit {want:?} vs decide_last {got:?}"))
            }
            None => Some(format!(
                "submit recorded a history event, decide_last decided {:?}",
                stateless_verdict(d)
            )),
        },
        (Ok(s), Err(e)) => match &s.outcome {
            Outcome::Recorded if e.to_string().contains("not a decision kind") => None,
            _ => Some(format!(
                "submit {:?} vs decide_last error {e}",
                durable_verdict(s, positions)
            )),
        },
        (Err(a), Err(b)) if a.to_string() == b.to_string() => None,
        (Err(a), b) => Some(format!(
            "submit error {a} vs decide_last {:?}",
            b.as_ref().map(stateless_verdict)
        )),
    }
}

/// The prefix ends to compare for a trajectory of `n` events.
fn select(n: usize, sample: Option<usize>) -> Vec<usize> {
    match sample {
        Some(k) if n > ALL_PREFIXES_UP_TO => {
            let mut chosen: BTreeSet<usize> = BTreeSet::from([n - 1]);
            chosen.extend((0..n).step_by((n / k).max(1)));
            let mut state = n as u64 * 2_654_435_761 + 1;
            for _ in 0..k {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                chosen.insert((state >> 33) as usize % n);
            }
            chosen.into_iter().collect()
        }
        _ => (0..n).collect(),
    }
}

// ─── The differential pass ───────────────────────────────────────────

#[derive(Default)]
struct DiffResult {
    events: usize,
    compared: usize,
    decisions: usize,
    rejected: bool,
    mismatches: Vec<Value>,
    /// Merged trajectories: events whose merged outcome was compared with the
    /// same event's outcome in its member replayed alone, and how many differed.
    isolation_compared: usize,
    isolation_mismatches: usize,
    /// Merged trajectories whose members share a principal (isolation not checked).
    shared_principal: bool,
    /// What the history cache did for this trajectory's calls.
    cache: HistoryCacheStats,
}

fn positions_of(engine: &DurableTemporalEngine) -> HashMap<String, usize> {
    engine
        .list()
        .iter()
        .enumerate()
        .map(|(i, p)| (p.token.to_string(), i))
        .collect()
}

/// `None` when two durable outcomes agree (each read with its own engine's tokens).
fn same_outcome(
    a: &Result<Submitted, DurableError>,
    a_positions: &HashMap<String, usize>,
    b: &Result<Submitted, DurableError>,
    b_positions: &HashMap<String, usize>,
) -> Option<String> {
    match (a, b) {
        (Ok(a), Ok(b)) => {
            let (va, vb) = (
                durable_verdict(a, a_positions),
                durable_verdict(b, b_positions),
            );
            (va != vb).then(|| format!("merged {va:?} vs alone {vb:?}"))
        }
        (Err(a), Err(b)) if a.to_string() == b.to_string() => None,
        (a, b) => Some(format!(
            "merged {:?} vs alone {:?}",
            a.as_ref().map(|s| durable_verdict(s, a_positions)),
            b.as_ref().map(|s| durable_verdict(s, b_positions))
        )),
    }
}

/// The isolation check for a merged trajectory: every member, replayed alone
/// through a fresh durable engine at the timestamps it had in the merged
/// history, must reach exactly the outcomes its events reached in the merged
/// run. Under a principal pin, other members' events are invisible to it.
fn isolation(
    t: &Trajectory,
    bundle: &Bundle,
    merged: &[Result<Submitted, DurableError>],
    merged_positions: &HashMap<String, usize>,
    r: &mut DiffResult,
) {
    let mut owner: HashMap<String, usize> = HashMap::new();
    for (j, m) in t.members.iter().enumerate() {
        for &i in &m.indices {
            if let Some(p) = t.events[i].principal()
                && *owner.entry(p).or_insert(j) != j
            {
                r.shared_principal = true;
                return;
            }
        }
    }
    for m in &t.members {
        let first = t.events[m.indices[0]].timestamp();
        let Ok((mut alone, clock, _)) = durable(bundle, first, None, &m.id) else {
            continue; // a set install rejects; the merged run reported it
        };
        let alone_positions = positions_of(&alone);
        for &i in &m.indices {
            let event = &t.events[i];
            clock.0.store(event.timestamp(), Ordering::SeqCst);
            let out = alone.submit(event.clone().into_builder());
            r.isolation_compared += 1;
            if let Some(what) = same_outcome(&merged[i], merged_positions, &out, &alone_positions) {
                r.isolation_mismatches += 1;
                r.mismatches.push(
                    json!({"trajectory": t.id, "source": t.source, "bundle": bundle.name,
                    "member": m.id, "index": i, "what": format!("isolation: {what}"),
                    "event": format!("{event:?}")}),
                );
            }
        }
    }
}

fn diff(
    t: &Trajectory,
    bundle: &Bundle,
    stateless: &mut Result<StatelessTemporalEngine, String>,
    sample: Option<usize>,
) -> DiffResult {
    let mut r = DiffResult {
        events: t.events.len(),
        ..DiffResult::default()
    };
    let mismatch = |r: &mut DiffResult, index: Option<usize>, what: String| {
        r.mismatches.push(json!({"trajectory": t.id, "source": t.source, "bundle": bundle.name, "index": index, "what": what,
            "event": index.map(|i| format!("{:?}", t.events[i]))}));
    };
    let Some(first) = t.events.first() else {
        return r;
    };
    let installed = durable(bundle, first.timestamp(), None, &t.id);
    let engine = match (installed, &mut *stateless) {
        (Ok((engine, clock, _)), Ok(engine_s)) => (engine, clock, engine_s),
        (Err(install), Err(compile)) => {
            if install != *compile {
                mismatch(
                    &mut r,
                    None,
                    format!("install rejected with {install:?}, compile with {compile:?}"),
                );
            }
            r.rejected = true;
            return r;
        }
        (Ok(_), Err(compile)) => {
            mismatch(
                &mut r,
                None,
                format!("install accepted, compile rejected: {compile}"),
            );
            return r;
        }
        (Err(install), Ok(_)) => {
            mismatch(
                &mut r,
                None,
                format!("compile accepted, install rejected: {install}"),
            );
            return r;
        }
    };
    let (mut durable_engine, clock, stateless) = engine;
    let cache_before = stateless.history_cache_stats();
    let outcomes: Vec<Result<Submitted, DurableError>> = t
        .events
        .iter()
        .map(|e| {
            clock.0.store(e.timestamp(), Ordering::SeqCst);
            durable_engine.submit(e.clone().into_builder())
        })
        .collect();
    let positions = positions_of(&durable_engine);
    if !t.members.is_empty() {
        isolation(t, bundle, &outcomes, &positions, &mut r);
    }
    for i in select(t.events.len(), sample) {
        let decided = stateless.decide_last(&t.events[..=i]);
        r.compared += 1;
        r.decisions += usize::from(decided.is_ok());
        if let Some(what) = compare(&outcomes[i], &positions, &decided) {
            mismatch(&mut r, Some(i), what);
        }
    }
    let after = stateless.history_cache_stats();
    r.cache = HistoryCacheStats {
        calls: after.calls - cache_before.calls,
        exact_hits: after.exact_hits - cache_before.exact_hits,
        prefix_hits: after.prefix_hits - cache_before.prefix_hits,
        misses: after.misses - cache_before.misses,
        reused_events: after.reused_events - cache_before.reused_events,
        replayed_events: after.replayed_events - cache_before.replayed_events,
    };
    r
}

// ─── The latency pass ────────────────────────────────────────────────

#[derive(Default)]
struct Latency {
    compile: Vec<Duration>,
    install: Vec<Duration>,
    submit: Vec<Duration>,
    submit_file: Vec<Duration>,
    /// (history length, call time)
    stateless: Vec<(usize, Duration)>,
    /// The same calls on an engine with the history cache (when on).
    stateless_cached: Vec<(usize, Duration)>,
    /// (stateful: all submits, stateless: one call per decision, the same
    /// with the history cache), per trajectory
    live_totals: Vec<(Duration, Duration, Duration)>,
    trajectories: usize,
}

fn measure(
    trajectories: &[&Trajectory],
    bundles: &[Bundle],
    sample: Option<usize>,
    file_dir: Option<&Path>,
    history_cache: usize,
) -> Latency {
    let mut l = Latency::default();
    let mut compiled: HashMap<usize, StatelessTemporalEngine> = HashMap::new();
    let mut cached: HashMap<usize, StatelessTemporalEngine> = HashMap::new();
    for t in trajectories {
        let bundle = &bundles[t.bundle];
        let Some(first) = t.events.first() else {
            continue;
        };
        let started = Instant::now();
        let Ok((mut engine, clock, _)) = durable(bundle, first.timestamp(), None, &t.id) else {
            continue;
        };
        l.install.push(started.elapsed());
        if let Entry::Vacant(slot) = compiled.entry(t.bundle) {
            let started = Instant::now();
            let Ok(s) = compile(bundle, 0) else { continue };
            l.compile.push(started.elapsed());
            slot.insert(s);
            if history_cache > 0
                && let Ok(c) = compile(bundle, history_cache)
            {
                cached.insert(t.bundle, c);
            }
        }
        let stateless = compiled.get_mut(&t.bundle).expect("compiled above");
        let mut with_cache = cached.get_mut(&t.bundle);
        l.trajectories += 1;

        let mut all_submits = Duration::ZERO;
        let mut decisions = Vec::new();
        for (i, e) in t.events.iter().enumerate() {
            clock.0.store(e.timestamp(), Ordering::SeqCst);
            let started = Instant::now();
            let out = engine.submit(e.clone().into_builder());
            let took = started.elapsed();
            all_submits += took;
            if matches!(
                out,
                Ok(Submitted {
                    outcome: Outcome::Decision(_),
                    ..
                })
            ) {
                l.submit.push(took);
                decisions.push(i);
            }
        }
        if let Some(dir) = file_dir
            && let Ok((mut file_engine, clock, path)) = durable(
                bundle,
                first.timestamp(),
                Some(dir),
                &format!("lat{}", l.trajectories),
            )
        {
            for e in &t.events {
                clock.0.store(e.timestamp(), Ordering::SeqCst);
                let started = Instant::now();
                let out = file_engine.submit(e.clone().into_builder());
                if matches!(
                    out,
                    Ok(Submitted {
                        outcome: Outcome::Decision(_),
                        ..
                    })
                ) {
                    l.submit_file.push(started.elapsed());
                }
            }
            drop(file_engine);
            if let Some(p) = path {
                let _ = std::fs::remove_file(p);
            }
        }

        let selected: BTreeSet<usize> = select(t.events.len(), sample).into_iter().collect();
        let mut every_decision = Duration::ZERO;
        let mut every_decision_cached = Duration::ZERO;
        let mut covered = true;
        for &i in &decisions {
            if !selected.contains(&i) {
                covered = false;
                continue;
            }
            let started = Instant::now();
            let _ = stateless.decide_last(&t.events[..=i]);
            let took = started.elapsed();
            every_decision += took;
            l.stateless.push((i + 1, took));
            if let Some(c) = with_cache.as_deref_mut() {
                let started = Instant::now();
                let _ = c.decide_last(&t.events[..=i]);
                let took = started.elapsed();
                every_decision_cached += took;
                l.stateless_cached.push((i + 1, took));
            }
        }
        if covered && !decisions.is_empty() {
            l.live_totals
                .push((all_submits, every_decision, every_decision_cached));
        }
    }
    l
}

// ─── Reporting ───────────────────────────────────────────────────────

fn pct(mut v: Vec<Duration>, p: f64) -> Duration {
    if v.is_empty() {
        return Duration::ZERO;
    }
    v.sort_unstable();
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn summary(v: &[Duration]) -> Value {
    json!({"n": v.len(), "p50_us": us(pct(v.to_vec(), 0.5)), "p99_us": us(pct(v.to_vec(), 0.99)), "max_us": us(pct(v.to_vec(), 1.0))})
}

const BUCKETS: [(usize, usize, &str); 5] = [
    (1, 10, "<10"),
    (10, 100, "10–99"),
    (100, 1_000, "100–999"),
    (1_000, 10_000, "1k–9.9k"),
    (10_000, usize::MAX, "≥10k"),
];

fn by_history(calls: &[(usize, Duration)]) -> Vec<Value> {
    BUCKETS
        .iter()
        .filter_map(|&(lo, hi, label)| {
            let calls: Vec<(usize, Duration)> = calls.iter().copied().filter(|(n, _)| *n >= lo && *n < hi).collect();
            if calls.is_empty() {
                return None;
            }
            let per_event: Vec<Duration> = calls.iter().map(|(n, d)| *d / *n as u32).collect();
            let times: Vec<Duration> = calls.iter().map(|(_, d)| *d).collect();
            Some(json!({"history": label, "calls": calls.len(), "p50_us": us(pct(times.clone(), 0.5)),
                "p99_us": us(pct(times, 0.99)), "us_per_event_p50": us(pct(per_event, 0.5))}))
        })
        .collect()
}

fn latency_json(l: &Latency) -> Value {
    let ratios: Vec<Duration> = l
        .live_totals
        .iter()
        .map(|(stateful, stateless, _)| {
            Duration::from_secs_f64(stateless.as_secs_f64() / stateful.as_secs_f64().max(1e-9))
        })
        .collect();
    json!({
        "trajectories": l.trajectories,
        "compile": summary(&l.compile),
        "durable_install": summary(&l.install),
        "durable_submit_decision": summary(&l.submit),
        "durable_file_submit_decision": summary(&l.submit_file),
        "stateless_call_by_history": by_history(&l.stateless),
        "stateless_cached_call_by_history": by_history(&l.stateless_cached),
        "live_every_decision": {
            "trajectories": l.live_totals.len(),
            "stateful_total_ms_p50": us(pct(l.live_totals.iter().map(|t| t.0).collect(), 0.5)) / 1000.0,
            "stateless_total_ms_p50": us(pct(l.live_totals.iter().map(|t| t.1).collect(), 0.5)) / 1000.0,
            "stateless_cached_total_ms_p50": us(pct(l.live_totals.iter().map(|t| t.2).collect(), 0.5)) / 1000.0,
            "stateless_over_stateful_p50": pct(ratios, 0.5).as_secs_f64(),
        }
    })
}

fn markdown(sources: &[(String, Value)]) {
    println!("\n## Differential\n");
    println!(
        "| Source | Trajectories | Events | Prefixes compared | Decisions | Mismatches | Rejected (both) | Isolation: events compared / violations |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for (name, s) in sources {
        let d = &s["diff"];
        let compared = d["isolation_compared"].as_u64().unwrap_or(0);
        let shared = d["shared_principal_groups"].as_u64().unwrap_or(0);
        let isolation = match (compared, shared) {
            (0, 0) => "n/a".to_string(),
            (0, s) => format!("not checked: {s} group(s) share a principal"),
            (c, 0) => format!("{c} / {}", d["isolation_mismatches"]),
            (c, s) => format!(
                "{c} / {} ({s} group(s) share a principal, not checked)",
                d["isolation_mismatches"]
            ),
        };
        println!(
            "| {name} | {} | {} | {} | {} | {} | {} | {isolation} |",
            d["trajectories"],
            d["events"],
            d["prefixes_compared"],
            d["decisions"],
            d["mismatches"],
            d["rejected_trajectories"]
        );
    }
    if sources
        .iter()
        .any(|(_, s)| s["diff"]["history_cache"]["calls"].as_u64().unwrap_or(0) > 0)
    {
        println!("\n## History cache (differential pass)\n");
        println!(
            "| Source | Calls | Prefix hits | Exact hits | Misses | Events replayed | Events reused |"
        );
        println!("|---|---|---|---|---|---|---|");
        for (name, s) in sources {
            let c = &s["diff"]["history_cache"];
            println!(
                "| {name} | {} | {} | {} | {} | {} | {} |",
                c["calls"],
                c["prefix_hits"],
                c["exact_hits"],
                c["misses"],
                c["replayed_events"],
                c["reused_events"]
            );
        }
    }
    println!("\n## Latency (single-threaded sample)\n");
    println!(
        "| Source | Sampled | Compile p50 | Durable submit p50 / p99 | On disk p50 / p99 | Stateless call p50 by history | Live, every decision: stateful / stateless (p50) |"
    );
    println!("|---|---|---|---|---|---|---|");
    for (name, s) in sources {
        let l = &s["latency"];
        let f = |v: &Value| format!("{:.0} µs", v.as_f64().unwrap_or(0.0));
        let bucket_list = |key: &str| -> Vec<String> {
            l[key]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|b| {
                            format!(
                                "{}: {}",
                                b["history"].as_str().unwrap_or(""),
                                f(&b["p50_us"])
                            )
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let buckets = bucket_list("stateless_call_by_history");
        let cached = bucket_list("stateless_cached_call_by_history");
        let disk = if l["durable_file_submit_decision"]["n"].as_u64().unwrap_or(0) > 0 {
            format!(
                "{} / {}",
                f(&l["durable_file_submit_decision"]["p50_us"]),
                f(&l["durable_file_submit_decision"]["p99_us"])
            )
        } else {
            "n/a".to_string()
        };
        let live = &l["live_every_decision"];
        // Only trajectories whose every decision was timed (not sampled) count.
        let live = if live["trajectories"].as_u64().unwrap_or(0) > 0 {
            let mut text = format!(
                "{:.2} ms / {:.2} ms",
                live["stateful_total_ms_p50"].as_f64().unwrap_or(0.0),
                live["stateless_total_ms_p50"].as_f64().unwrap_or(0.0)
            );
            if !cached.is_empty() {
                text += &format!(
                    " / cached {:.2} ms",
                    live["stateless_cached_total_ms_p50"]
                        .as_f64()
                        .unwrap_or(0.0)
                );
            }
            text
        } else {
            "n/a (sampled)".to_string()
        };
        let calls = if cached.is_empty() {
            buckets.join(", ")
        } else {
            format!("{}<br>cached: {}", buckets.join(", "), cached.join(", "))
        };
        println!(
            "| {name} | {} | {} | {} / {} | {disk} | {calls} | {live} |",
            l["trajectories"],
            f(&l["compile"]["p50_us"]),
            f(&l["durable_submit_decision"]["p50_us"]),
            f(&l["durable_submit_decision"]["p99_us"]),
        );
    }
}

fn main() {
    let cfg = Config::from_args();
    let mut bundles = Vec::new();
    let mut trajectories = Vec::new();
    if let Some(dir) = &cfg.corpus {
        load_corpus(dir, &mut bundles, &mut trajectories);
        add_merged(&cfg.merge, &mut trajectories);
    }
    if cfg.synthetic {
        add_synthetic(&mut bundles, &mut trajectories);
    }
    eprintln!(
        "{} trajectories, {} policy sets, {} threads",
        trajectories.len(),
        bundles.len(),
        cfg.threads
    );

    // Differential pass: parallel, each worker compiling each policy set once.
    let started = Instant::now();
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, DiffResult)>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..cfg.threads.max(1) {
            scope.spawn(|| {
                let mut compiled: HashMap<usize, Result<StatelessTemporalEngine, String>> =
                    HashMap::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(t) = trajectories.get(i) else { break };
                    let bundle = &bundles[t.bundle];
                    let stateless = compiled
                        .entry(t.bundle)
                        .or_insert_with(|| compile(bundle, cfg.history_cache));
                    let r = diff(t, bundle, stateless, cfg.prefixes);
                    results.lock().unwrap().push((i, r));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    let diff_secs = started.elapsed().as_secs_f64();

    let mut source_names: Vec<String> = trajectories.iter().map(|t| t.source.clone()).collect();
    source_names.sort();
    source_names.dedup();

    let mut sources = Vec::new();
    let mut all_mismatches = Vec::new();
    for name in &source_names {
        let rs: Vec<&DiffResult> = results
            .iter()
            .filter(|(i, _)| trajectories[*i].source == *name)
            .map(|(_, r)| r)
            .collect();
        let mismatches: Vec<Value> = rs
            .iter()
            .flat_map(|r| r.mismatches.iter().cloned())
            .collect();
        let diff = json!({
            "trajectories": rs.len(),
            "events": rs.iter().map(|r| r.events).sum::<usize>(),
            "prefixes_compared": rs.iter().map(|r| r.compared).sum::<usize>(),
            "decisions": rs.iter().map(|r| r.decisions).sum::<usize>(),
            "rejected_trajectories": rs.iter().filter(|r| r.rejected).count(),
            "mismatches": mismatches.len(),
            "isolation_compared": rs.iter().map(|r| r.isolation_compared).sum::<usize>(),
            "isolation_mismatches": rs.iter().map(|r| r.isolation_mismatches).sum::<usize>(),
            "shared_principal_groups": rs.iter().filter(|r| r.shared_principal).count(),
            "history_cache": {
                "capacity": cfg.history_cache,
                "calls": rs.iter().map(|r| r.cache.calls).sum::<u64>(),
                "prefix_hits": rs.iter().map(|r| r.cache.prefix_hits).sum::<u64>(),
                "exact_hits": rs.iter().map(|r| r.cache.exact_hits).sum::<u64>(),
                "misses": rs.iter().map(|r| r.cache.misses).sum::<u64>(),
                "replayed_events": rs.iter().map(|r| r.cache.replayed_events).sum::<u64>(),
                "reused_events": rs.iter().map(|r| r.cache.reused_events).sum::<u64>(),
            },
        });
        all_mismatches.extend(mismatches);

        // Latency: an evenly spaced, single-threaded sample of this source.
        let members: Vec<&Trajectory> = trajectories.iter().filter(|t| t.source == *name).collect();
        let step = (members.len() / cfg.latency_trajectories.max(1)).max(1);
        let sample: Vec<&Trajectory> = members
            .iter()
            .step_by(step)
            .take(cfg.latency_trajectories)
            .copied()
            .collect();
        eprintln!("measuring {name}: {} trajectories", sample.len());
        let latency = latency_json(&measure(
            &sample,
            &bundles,
            cfg.prefixes,
            cfg.durable_dir.as_deref(),
            cfg.history_cache,
        ));
        sources.push((name.clone(), json!({"diff": diff, "latency": latency})));
    }

    markdown(&sources);
    let total_compared: u64 = sources
        .iter()
        .map(|(_, s)| s["diff"]["prefixes_compared"].as_u64().unwrap_or(0))
        .sum();
    println!(
        "\n{} prefixes compared in {diff_secs:.1} s across {} trajectories: {} mismatch(es)",
        total_compared,
        trajectories.len(),
        all_mismatches.len()
    );
    for m in all_mismatches.iter().take(20) {
        println!("  {m}");
    }

    let report = cfg.report.clone().unwrap_or_else(|| {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
        PathBuf::from(target)
            .join("stateless-diff")
            .join(format!("report-{secs}.json"))
    });
    if let Some(parent) = report.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body = json!({
        "sources": sources.iter().map(|(n, s)| (n.clone(), s.clone())).collect::<serde_json::Map<_, _>>(),
        "mismatches": all_mismatches,
        "prefixes": cfg.prefixes.map(|k| k.to_string()).unwrap_or_else(|| "all".to_string()),
        "threads": cfg.threads,
        "durable_dir": cfg.durable_dir.as_ref().map(|d| d.display().to_string()),
        "history_cache": cfg.history_cache,
    });
    std::fs::write(&report, serde_json::to_string_pretty(&body).unwrap()).expect("write report");
    println!("report: {}", report.display());
    if !all_mismatches.is_empty() {
        std::process::exit(1);
    }
}
