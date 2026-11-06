//! Stateless decisions: `StatelessTemporalEngine::decide_last` against the
//! durable engine, across history length and session pinning, plus what
//! compiling a policy set costs.
//!
//! # What is measured
//!
//! - `stateless_compile/{pinning}/{10,100,1000}p`: `StatelessTemporalEngine::new`,
//!   the one-time cost a caller pays per policy set.
//! - `decide_after_history/{arm}/{pinning}/{n}`, at 100 policies, deciding one
//!   event after `n` events of history:
//!   - `stateless`: a compiled engine's `decide_last(history + probe)`. Every call
//!     resets the engine and replays the whole history, so this grows with `n`.
//!   - `durable_submit`: the probe's `submit` on a durable engine already holding
//!     the history: the incremental engine's marginal cost per decision, which
//!     stays flat because state is kept between calls. As in `decide_latency`,
//!     the history is rebuilt per batch, so the measured engine grows across a
//!     batch and the mean is over a small window of history lengths.
//!   - `durable_replay`: a fresh durable engine installing the set and submitting
//!     history + probe, which is what answering statelessly with the durable
//!     engine would cost.
//!
//! The durable engines use an in-memory log, so no fsync is in these numbers.
//!
//! # Cross-check first
//!
//! Before any timing, every prefix of a 60-event stream is decided both ways and
//! must agree, with a mix of allows and denies, so the timings describe the same
//! computation.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dogwood_language::Event;
use dogwood_local_engine::{
    Clock, DurableConfig, DurableLog, DurableTemporalEngine, Outcome, StatelessTemporalEngine,
};
use dogwood_performance::driver::to_event;
use dogwood_performance::workload::{ACTION_SCHEMA, Pinning, event_stream, policy_set};

const SECOND: i64 = 1_000_000_000;
const T0: i64 = 1_700_000_000 * SECOND;
/// Distinct sessions, servers and the login cadence: `decide_latency`'s values
/// (servers coprime to the cadence, so allows and denies mix).
const SESSIONS: usize = 10;
const SERVERS: usize = 49;
const LOGIN_EVERY: usize = 5;
const POLICIES: usize = 100;
/// History lengths. At most 3,600 so the rules' one-hour window (events are a
/// second apart) never expires inside a history.
const HISTORIES: [usize; 4] = [10, 100, 1_000, 3_000];

#[derive(Clone)]
struct ManualClock(Arc<AtomicI64>);

impl Clock for ManualClock {
    fn now_nanos(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// `n` workload events, a second apart from `T0`, in nanoseconds.
fn events(n: usize) -> Vec<Event> {
    event_stream(n, SESSIONS, SERVERS, LOGIN_EVERY)
        .iter()
        .map(|e| {
            to_event(e)
                .into_builder()
                .timestamp(T0 + e.ts * SECOND)
                .build()
        })
        .collect()
}

fn durable(policies: usize, pinning: Pinning) -> (DurableTemporalEngine, ManualClock) {
    let clock = ManualClock(Arc::new(AtomicI64::new(T0 - SECOND)));
    let config = DurableConfig::new(0)
        .with_clock(Box::new(clock.clone()))
        .with_max_future_skew(Duration::from_secs(10 * 365 * 86_400));
    let log = DurableLog::ephemeral().expect("an in-memory log");
    let mut engine =
        DurableTemporalEngine::open_with_log_config(log, PathBuf::from("bench"), config)
            .expect("opens");
    engine
        .install(
            &policy_set(policies),
            ACTION_SCHEMA,
            Some(pinning.event_schema()),
            None,
        )
        .expect("installs");
    (engine, clock)
}

fn submit(engine: &mut DurableTemporalEngine, clock: &ManualClock, event: &Event) -> Option<bool> {
    clock.0.store(event.timestamp(), Ordering::SeqCst);
    match engine
        .submit(event.clone().into_builder())
        .expect("submits")
        .outcome
    {
        Outcome::Decision(r) => Some(r.allowed()),
        Outcome::Recorded => None,
    }
}

fn stateless(policies: usize, pinning: Pinning) -> StatelessTemporalEngine {
    StatelessTemporalEngine::new(
        &policy_set(policies),
        ACTION_SCHEMA,
        Some(pinning.event_schema()),
        None,
    )
    .expect("compiles")
}

fn cross_check(pinning: Pinning) {
    let history = events(60);
    let (mut d, clock) = durable(10, pinning);
    let mut s = stateless(10, pinning);
    let (mut allows, mut decisions) = (0, 0);
    for i in 0..history.len() {
        let want = submit(&mut d, &clock, &history[i]);
        let got = s
            .decide_last(&history[..=i])
            .ok()
            .map(|x| x.response.allowed());
        assert_eq!(
            want,
            got,
            "{}: event {i}: submit {want:?} vs decide_last {got:?}",
            pinning.label()
        );
        decisions += usize::from(want.is_some());
        allows += usize::from(want == Some(true));
    }
    assert!(
        allows > 0 && allows < decisions,
        "{}: the workload must mix allows and denies ({allows} of {decisions})",
        pinning.label()
    );
}

fn bench(c: &mut Criterion) {
    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        cross_check(pinning);
    }

    let mut compile = c.benchmark_group("stateless_compile");
    compile.sample_size(10);
    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        for policies in [10, 100, 1_000] {
            compile.bench_function(
                BenchmarkId::new(pinning.label(), format!("{policies}p")),
                |b| b.iter(|| stateless(policies, pinning)),
            );
        }
    }
    compile.finish();

    let mut decide = c.benchmark_group("decide_after_history");
    decide.sample_size(10);
    for pinning in [Pinning::Unpinned, Pinning::PinnedSession] {
        for n in HISTORIES {
            let history = events(n + 1);
            let id = |arm: &str| BenchmarkId::new(format!("{arm}/{}", pinning.label()), n);

            let mut engine = stateless(POLICIES, pinning);
            decide.bench_function(id("stateless"), |b| {
                b.iter(|| engine.decide_last(&history).expect("decides"))
            });

            // Probes continue the stream past the history, so each is a fresh event.
            let probes = events(n + 1 + 2_000);
            decide.bench_function(id("durable_submit"), |b| {
                b.iter_custom(|iters| {
                    let (mut d, clock) = durable(POLICIES, pinning);
                    for e in &history[..n] {
                        submit(&mut d, &clock, e);
                    }
                    let mut total = Duration::ZERO;
                    for k in 0..iters as usize {
                        let probe = &probes[n + k % 2_000];
                        let started = Instant::now();
                        submit(&mut d, &clock, probe);
                        total += started.elapsed();
                    }
                    total
                })
            });

            decide.bench_function(id("durable_replay"), |b| {
                b.iter(|| {
                    let (mut d, clock) = durable(POLICIES, pinning);
                    let mut last = None;
                    for e in &history {
                        last = submit(&mut d, &clock, e);
                    }
                    last
                })
            });
        }
    }
    decide.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
