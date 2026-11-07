//! Stateless decisions: a whole history in, the decision for its last event out.
//!
//! [`StatelessTemporalEngine`] compiles a policy set exactly as
//! [`DurableTemporalEngine::install`] does (the same canonicalization,
//! lowering, validation, pin partitioning and attribution, through the shared
//! `compile` step), and then answers
//! [`decide_last`](StatelessTemporalEngine::decide_last): given the events of a
//! history in time order, the decision `submit` would return for the last one on
//! a fresh durable engine that had just installed the same set and received the
//! same events at the same times.
//!
//! # How a call works
//!
//! The temporal engine is returned to its just-compiled, empty state, the
//! history before the last event is observed into it (exactly what recovery does
//! when it replays the log: monitors step, nothing is decided), and the last
//! event goes through the authorizer, which decides it. Deciding never changes
//! monitor state, so skipping the earlier decisions changes nothing about the
//! last one.
//!
//! There is no log, no clock and no durability, and by default nothing carries
//! from one call to the next. Compile once, decide many times: the compiled set
//! is the expensive part, and every call reuses it.
//!
//! # History cache
//!
//! In live use consecutive calls tend to send the same history with a few more
//! events. [`with_history_cache`](StatelessTemporalEngine::with_history_cache)
//! keeps the temporal state of up to `n` recent histories, so a call whose
//! history extends one of them replays only the new events, and a call that
//! repeats one returns its decision. A cached history is used only when the new
//! history's events equal it exactly, timestamps included; anything else is a
//! miss, which replays the whole history as without the cache. Decisions are
//! identical either way: the cache changes how much is replayed, never what is
//! decided. Each history keeps only its newest state, so a call that continues
//! from an earlier point of a history is a miss.

use std::borrow::Cow;
use std::fmt;

use dogwood_language::{Authorizer, Event, ServiceSchema, TemporalEngine};

use super::attribution::{RuleAttribution, attribute_response};
use super::{
    Compiled, DecisionResponse, DurableError, DurableTemporalEngine, Installed, Preparation,
    ServiceConfig, Status, assemble, checked_next_timestamp, compile, decision_without_response,
    reject_unresolved_transplant_origins,
};
use crate::LocalTemporalEngine;
use crate::policy_store::{PolicyEntry, PolicySet};
use crate::shared::SharedEngine;

/// A policy set compiled for stateless decisions. See the [module
/// docs](self).
///
/// # Timestamps
///
/// Every event carries its own timestamp, in epoch **nanoseconds**, the unit the
/// durable engine assigns. A history stamped in seconds still decides, but every
/// window would be a billion times too short. Timestamps must not decrease; equal
/// ones are spread one nanosecond apart, as `submit` does when its clock does not
/// advance, and [`Decided::ts`] reports where the last event landed.
///
/// # Attribution
///
/// Decisions carry [`PolicyAttribution`](super::PolicyAttribution)s like
/// `submit`'s, with the policies' annotations exactly as installed. The tokens are
/// deterministic placeholders (`SPref0`, `SPref1`, … in policy order, as
/// [`list`](Self::list) shows), not durable handles: no store ever holds them.
///
/// # Memory
///
/// Without the history cache, the temporal state built for a call stays
/// allocated until the next call (which discards it first), until
/// [`clear`](Self::clear), or until the engine is dropped. With it, each cached
/// history holds its events and its monitors' (window-bounded) state until it is
/// evicted, least recently used first, or cleared. Under a schema that declares
/// pins, each cached history's monitors also keep one background thread, so keep
/// the cache small (a few dozen at most).
pub struct StatelessTemporalEngine {
    /// The compiled bundle, kept to rebuild the engine if its lock is poisoned.
    installed: Installed,
    service: ServiceSchema,
    authorizer: Authorizer,
    /// The temporal engine the authorizer reads, shared so it can be reset, and
    /// so a cached history's monitors can be swapped in for a call.
    engine: SharedEngine,
    attributions: Vec<RuleAttribution>,
    preparation: Preparation,
    status: Status,
    /// Whether the engine holds a previous call's state.
    dirty: bool,
    /// The history cache: at most `capacity` entries (0 = off).
    cache: Vec<Entry>,
    capacity: usize,
    /// Advances on every cached call; an entry's `last_used` orders eviction.
    tick: u64,
    stats: HistoryCacheStats,
}

/// What the history cache has done since the engine was compiled (or since the
/// cache was turned on). Subtract two readings for one call's figures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryCacheStats {
    /// Calls made with the cache on, refused ones included (so it can exceed
    /// the sum of hits and misses).
    pub calls: u64,
    /// Calls whose history equalled a cached one: the decision was returned as is.
    pub exact_hits: u64,
    /// Calls whose history extended a cached one: only the new events were replayed.
    pub prefix_hits: u64,
    /// Calls that matched nothing cached and replayed the whole history.
    pub misses: u64,
    /// Events whose effect came from a cached state rather than a replay.
    pub reused_events: u64,
    /// Events replayed into the monitors, the decided one included.
    pub replayed_events: u64,
}

/// One cached history: its events, the monitors' state after all of them, and
/// the decision for the last one.
struct Entry {
    events: Vec<Event>,
    /// The timestamp the last event was decided at (after the tie clamp).
    last_ts: i64,
    decided: Decided,
    engine: LocalTemporalEngine,
    last_used: u64,
}

/// The decision for the last event of a history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    /// The timestamp (epoch nanoseconds) the last event was decided at: its own,
    /// unless a run of equal timestamps moved it later.
    pub ts: i64,
    /// The decision, as `submit` returns it.
    pub response: DecisionResponse,
}

impl StatelessTemporalEngine {
    /// Compile a policy set. The arguments are [`install`](DurableTemporalEngine::install)'s,
    /// and so are the outcomes: a set compiles here exactly when it would install
    /// on a fresh store, and a rejection carries the same message.
    pub fn new(
        policy_source: &str,
        action_schema: &str,
        event_schema: Option<&str>,
        macros: Option<&str>,
    ) -> Result<Self, DurableError> {
        let config = ServiceConfig {
            event_schema: event_schema.map(String::from),
            macros: macros.map(String::from),
        };
        let service = DurableTemporalEngine::build_service(&config)?;
        let statements = DurableTemporalEngine::canonicalize_source(policy_source, &service)
            .map_err(|e| DurableError::Rejected(format!("policy: {e}")))?;
        let installed = Installed {
            // A first install mints ids from 0 too; only the tokens differ.
            policies: PolicySet::from_statements(statements, 0),
            action_schema: action_schema.to_string(),
        };
        Self::from_installed(installed, service)
    }

    fn from_installed(installed: Installed, service: ServiceSchema) -> Result<Self, DurableError> {
        let Compiled {
            lowered,
            engine,
            attributions,
            decision_kinds,
            rule_count,
            leaf_count,
            incremental_leaves,
            leaf_keys: _,
            shard_plan: _,
            partition_key,
            preparation,
        } = compile(&installed, &service)?;
        // An install transplants into all-fresh leaves, whose only possible
        // rejection is this one.
        reject_unresolved_transplant_origins(&engine)?;
        let (engine, authorizer) = assemble(engine, lowered)?;
        Ok(Self {
            installed,
            service,
            authorizer,
            engine,
            attributions,
            preparation,
            status: Status {
                rule_count,
                leaf_count,
                incremental_leaves,
                decision_kinds,
                partition_key,
            },
            dirty: false,
            cache: Vec::new(),
            capacity: 0,
            tick: 0,
            stats: HistoryCacheStats::default(),
        })
    }

    /// Keep the temporal state of up to `entries` recent histories (0 turns the
    /// cache off, the default). See the [module docs](self#history-cache):
    /// decisions are the same with or without it. Lowering the capacity of an
    /// engine already in use keeps its most recently used histories.
    pub fn with_history_cache(mut self, entries: usize) -> Self {
        self.capacity = entries;
        if self.cache.len() > entries {
            self.cache
                .sort_by_key(|entry| std::cmp::Reverse(entry.last_used));
            self.cache.truncate(entries);
        }
        self
    }

    /// What the history cache has done so far.
    pub fn history_cache_stats(&self) -> HistoryCacheStats {
        self.stats
    }

    /// Decide the last event of `history`, given the events before it.
    ///
    /// `history` is in time order and its last event is of a decision kind
    /// ([`Status::decision_kinds`]); otherwise this is a
    /// [`DurableError::BadEvent`] and nothing is evaluated. A decision that cannot
    /// be evaluated (a missing attribute, say) is still `Ok`, as a deny with its
    /// errors, exactly as from `submit`.
    pub fn decide_last(&mut self, history: &[Event]) -> Result<Decided, DurableError> {
        if self.capacity > 0 {
            self.stats.calls += 1;
        }
        let Some(last) = history.last() else {
            return Err(DurableError::BadEvent(
                "history is empty; its last event is the one decided".to_string(),
            ));
        };
        if !self.status.decision_kinds.iter().any(|k| k == last.kind()) {
            return Err(DurableError::BadEvent(format!(
                "history[{}] has kind `{}`, which is not a decision kind (decision kinds: {})",
                history.len() - 1,
                last.kind(),
                self.status.decision_kinds.join(", "),
            )));
        }
        if self.capacity == 0 {
            self.decide_uncached(history)
        } else {
            self.decide_cached(history)
        }
    }

    /// Replay all of `history` into the scratch engine and decide its last event.
    fn decide_uncached(&mut self, history: &[Event]) -> Result<Decided, DurableError> {
        // Before any observation: a partitioned engine requires time order.
        let stamps = stamp_from(history, 0, None)?;
        let (last, earlier) = history.split_last().expect("checked non-empty");

        self.reset()?;
        self.dirty = true;
        self.engine
            .with_mut(|engine| {
                for (event, &ts) in earlier.iter().zip(&stamps) {
                    engine.observe(&at(event, ts));
                }
            })
            .ok_or_else(poisoned)?;
        self.decide(last, stamps[history.len() - 1])
    }

    /// Decide `history`'s last event from the cached state of its longest
    /// cached prefix, replaying only the events after it.
    fn decide_cached(&mut self, history: &[Event]) -> Result<Decided, DurableError> {
        self.tick += 1;
        let now = self.tick;
        let n = history.len();

        // The longest cached history that `history` starts with. Entries never
        // repeat a history, so one as long as `history` is all of it.
        let mut best: Option<usize> = None;
        for (i, entry) in self.cache.iter().enumerate() {
            let longer = best.is_none_or(|b| entry.events.len() > self.cache[b].events.len());
            if longer && starts_with(history, &entry.events) {
                best = Some(i);
            }
        }
        if let Some(i) = best
            && self.cache[i].events.len() == n
        {
            let entry = &mut self.cache[i];
            entry.last_used = now;
            self.stats.exact_hits += 1;
            self.stats.reused_events += n as u64;
            return Ok(entry.decided.clone());
        }

        // Only what is new needs stamping (and checking): the cached prefix was
        // checked when it was decided, and its stamps are the ones it had then.
        let (from, before) = match best {
            Some(i) => (self.cache[i].events.len(), Some(self.cache[i].last_ts)),
            None => (0, None),
        };
        let stamps = stamp_from(history, from, before)?;
        // A poisoned lock means an earlier call panicked; rebuild before
        // swapping a cached engine into it.
        if self.engine.with(|_| ()).is_none() {
            self.rebuild()?; // keeps the cache, in order, so `best` still names it
        }

        // Take the slot out of the cache for the call, so a failure drops it
        // rather than leaving it half updated.
        let (engine, mut events) = match best {
            Some(i) => {
                let Entry { engine, events, .. } = self.cache.swap_remove(i);
                (engine, events)
            }
            None => self.vacancy(n)?,
        };

        // Swap the slot's monitors in where the authorizer reads them, replay
        // the new events, decide the last, and swap the scratch engine back.
        let mut incoming = Some(engine);
        let scratch = self
            .engine
            .with_mut(|slot| std::mem::replace(slot, incoming.take().expect("swapped once")))
            .ok_or_else(poisoned)?;
        let (new_earlier, new_stamps) = (&history[from..n - 1], &stamps[..stamps.len() - 1]);
        let ts = stamps[stamps.len() - 1];
        let decided = self
            .engine
            .with_mut(|engine| {
                for (event, &ts) in new_earlier.iter().zip(new_stamps) {
                    engine.observe(&at(event, ts));
                }
            })
            .ok_or_else(poisoned)
            .and_then(|()| self.decide(&history[n - 1], ts));
        let mut outgoing = Some(scratch);
        let engine = self
            .engine
            .with_mut(|slot| std::mem::replace(slot, outgoing.take().expect("swapped once")))
            .ok_or_else(poisoned)?;
        let decided = decided?;

        events.extend_from_slice(&history[from..]);
        self.cache.push(Entry {
            events,
            last_ts: ts,
            decided: decided.clone(),
            engine,
            last_used: now,
        });
        if from == 0 {
            self.stats.misses += 1;
        } else {
            self.stats.prefix_hits += 1;
        }
        self.stats.reused_events += from as u64;
        self.stats.replayed_events += (n - from) as u64;
        Ok(decided)
    }

    /// Decide `last` at `ts` against whatever state the shared engine holds.
    fn decide(&mut self, last: &Event, ts: i64) -> Result<Decided, DurableError> {
        let last = at(last, ts);
        match self.authorizer.is_authorized(&last) {
            Some(response) => Ok(Decided {
                ts,
                response: attribute_response(&response, &self.attributions),
            }),
            None => Err(decision_without_response(&last)),
        }
    }

    /// An empty engine, and a buffer for a history of `n` events, for a history
    /// nothing cached starts: a new one while the cache has room, else the least
    /// recently used entry's, reset (which keeps its background thread, if any).
    fn vacancy(&mut self, n: usize) -> Result<(LocalTemporalEngine, Vec<Event>), DurableError> {
        if self.cache.len() < self.capacity {
            return Ok((self.preparation.fresh()?, Vec::with_capacity(n)));
        }
        let lru = (0..self.cache.len())
            .min_by_key(|&i| self.cache[i].last_used)
            .expect("a full cache of capacity > 0 has an entry");
        let Entry {
            mut engine,
            mut events,
            ..
        } = self.cache.swap_remove(lru);
        self.preparation.reset(&mut engine)?;
        events.clear();
        Ok((engine, events))
    }

    /// The compiled set, as [`DurableTemporalEngine::status`] reports it after
    /// installing the same set.
    pub fn status(&self) -> Status {
        self.status.clone()
    }

    /// The compiled policies in order, with their placeholder tokens.
    pub fn list(&self) -> Vec<PolicyEntry> {
        self.installed.policies.entries().cloned().collect()
    }

    /// The temporal engine's live shard count, as after the last call (0 when
    /// global or unused): the observable that pins partitioned mode. With the
    /// history cache on, the count of the most recently used history's monitors.
    #[doc(hidden)]
    pub fn temporal_shard_count(&self) -> usize {
        match self.cache.iter().max_by_key(|entry| entry.last_used) {
            Some(entry) => entry.engine.shard_count(),
            None => self.engine.with(|e| e.shard_count()).unwrap_or(0),
        }
    }

    /// Discard the temporal state calls have left: the last call's, which
    /// [`decide_last`](Self::decide_last) would otherwise discard at the start of
    /// the next call, and every history the cache holds. Calling this after a
    /// decision moves that work (and the freeing of its memory) to a time of the
    /// caller's choosing, such as after a reply has been sent. It changes no
    /// decision. With the cache on, it also empties the cache, so the next calls
    /// replay their whole histories.
    pub fn clear(&mut self) -> Result<(), DurableError> {
        self.cache.clear();
        self.reset()
    }

    /// Return the temporal engine to its just-compiled, empty state.
    fn reset(&mut self) -> Result<(), DurableError> {
        if !self.dirty {
            return Ok(());
        }
        let preparation = &self.preparation;
        match self.engine.with_mut(|engine| preparation.reset(engine)) {
            Some(result) => result?,
            // A poisoned engine: a previous call panicked mid-way. Every call
            // starts from empty state anyway, so rebuilding loses nothing.
            None => self.rebuild()?,
        }
        self.dirty = false;
        Ok(())
    }

    /// Recompile after a poisoned lock, keeping the history cache: its entries'
    /// engines were never in the poisoned slot between calls, so they are sound.
    fn rebuild(&mut self) -> Result<(), DurableError> {
        let mut rebuilt = Self::from_installed(self.installed.clone(), self.service.clone())?;
        rebuilt.cache = std::mem::take(&mut self.cache);
        rebuilt.capacity = self.capacity;
        rebuilt.tick = self.tick;
        rebuilt.stats = self.stats;
        *self = rebuilt;
        Ok(())
    }
}

impl fmt::Debug for StatelessTemporalEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessTemporalEngine")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Compile a policy set and decide the last event of one history: a
/// [`StatelessTemporalEngine`] used once. To decide several histories against
/// the same set, keep the engine instead.
pub fn decide_last(
    policy_source: &str,
    action_schema: &str,
    event_schema: Option<&str>,
    macros: Option<&str>,
    history: &[Event],
) -> Result<Decided, DurableError> {
    StatelessTemporalEngine::new(policy_source, action_schema, event_schema, macros)?
        .decide_last(history)
}

/// The timestamp each event of `history[from..]` is evaluated at: its own, moved
/// one nanosecond past the previous one where they tie (`submit`'s
/// `max(now, last + 1)`), continuing from `before`, the stamp of
/// `history[from - 1]` (`None` when `from` is 0). A timestamp lower than the one
/// before it is refused rather than moved, because moving it would shift its
/// windows.
fn stamp_from(
    history: &[Event],
    from: usize,
    before: Option<i64>,
) -> Result<Vec<i64>, DurableError> {
    let mut stamps: Vec<i64> = Vec::with_capacity(history.len() - from);
    let mut previous = before;
    for (i, event) in history.iter().enumerate().skip(from) {
        let given = event.timestamp();
        if i > 0 {
            let before = history[i - 1].timestamp();
            if given < before {
                return Err(DurableError::BadEvent(format!(
                    "history[{i}] timestamp {given} is before history[{}] timestamp {before}; \
                     events must be in time order",
                    i - 1
                )));
            }
        }
        let assigned = checked_next_timestamp(previous, given).ok_or_else(|| {
            DurableError::BadEvent(format!(
                "history[{i}] cannot be stamped: no timestamp follows {}",
                previous.unwrap_or(given)
            ))
        })?;
        stamps.push(assigned);
        previous = Some(assigned);
    }
    Ok(stamps)
}

/// Whether `history` starts with `cached` (or is it). The ends are compared
/// before the rest: a different history usually differs there.
fn starts_with(history: &[Event], cached: &[Event]) -> bool {
    let k = cached.len();
    k > 0
        && k <= history.len()
        && cached[0] == history[0]
        && cached[k - 1] == history[k - 1]
        && cached == &history[..k]
}

/// `event` at `ts`, borrowed unless a tie moved it.
fn at(event: &Event, ts: i64) -> Cow<'_, Event> {
    if event.timestamp() == ts {
        Cow::Borrowed(event)
    } else {
        Cow::Owned(event.clone().into_builder().timestamp(ts).build())
    }
}

fn poisoned() -> DurableError {
    DurableError::Log("temporal engine unavailable (poisoned)".to_string())
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use dogwood_language::{UNPINNED_EVENT_SCHEMA, Value};

    use super::*;

    const SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };
action Export appliesTo { principal: User, resource: Doc, context: { input: { doc: String } } };
"#;
    const POLICY: &str = r#"
permit (principal, action, resource);
forbid (principal, action == Action::"Export", resource)
when temporal { formerly within 1h Action::"Read"::response{} };
"#;
    const T0: i64 = 1_700_000_000_000_000_000;

    fn ev(action: &str, kind: &str, who: &str, ts: i64) -> Event {
        let doc = Value::String("d1".to_string());
        Event::builder(&format!("Action::{action}"), kind)
            .principal(&format!("User::\"{who}\""))
            .resource("Doc::\"d1\"")
            .field("input", "doc", doc.clone())
            .request_context("input", "doc", doc)
            .timestamp(ts)
            .build()
    }

    fn history() -> Vec<Event> {
        vec![
            ev("Read", "response", "alice", T0),
            ev("Read", "response", "bob", T0 + 1),
            ev("Export", "request", "alice", T0 + 2),
        ]
    }

    fn snapshot(e: &StatelessTemporalEngine) -> Vec<u8> {
        e.engine
            .with(|engine| engine.save_snapshot())
            .expect("not poisoned")
    }

    #[test]
    fn a_reset_returns_the_engine_to_its_compiled_state() {
        for event_schema in [None, Some(UNPINNED_EVENT_SCHEMA)] {
            let mut e = StatelessTemporalEngine::new(POLICY, SCHEMA, event_schema, None).unwrap();
            let compiled = snapshot(&e);
            let d = e.decide_last(&history()).unwrap();
            assert!(
                !d.response.allowed(),
                "{event_schema:?}: the read arms the forbid"
            );
            assert_ne!(
                snapshot(&e),
                compiled,
                "{event_schema:?}: the call left state"
            );
            e.reset().unwrap();
            assert_eq!(snapshot(&e), compiled, "{event_schema:?}");
            assert_eq!(e.temporal_shard_count(), 0, "{event_schema:?}");
            assert!(!e.dirty);
        }
    }

    #[test]
    fn clear_empties_the_engine_and_changes_no_decision() {
        let mut e = StatelessTemporalEngine::new(POLICY, SCHEMA, None, None).unwrap();
        let compiled = snapshot(&e);
        let first = e.decide_last(&history()).unwrap();
        e.clear().unwrap();
        assert_eq!(snapshot(&e), compiled, "cleared to the compiled state");
        assert!(!e.dirty, "the next call has nothing to reset");
        e.clear().unwrap(); // clearing an empty engine is a no-op
        assert_eq!(e.decide_last(&history()).unwrap(), first);
    }

    #[test]
    fn a_poisoned_engine_is_rebuilt_by_the_next_call() {
        let mut e = StatelessTemporalEngine::new(POLICY, SCHEMA, None, None).unwrap();
        let expected = e.decide_last(&history()).unwrap();
        let shared = e.engine.clone();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            shared.with_mut(|_| panic!("poison the engine lock"));
        }));
        assert!(panic.is_err());
        assert!(e.engine.with(|_| ()).is_none(), "lock was not poisoned");

        let again = e.decide_last(&history()).unwrap();
        assert_eq!(again.ts, expected.ts);
        assert_eq!(again.response.allowed(), expected.response.allowed());
        assert!(
            e.engine.with(|_| ()).is_some(),
            "rebuilt with a healthy lock"
        );
    }
    fn longer_history() -> Vec<Event> {
        let mut h = Vec::new();
        for i in 0..12 {
            let who = ["alice", "bob", "carol"][i % 3];
            let ts = T0 + i as i64 * 600_000_000_000; // 10 minutes apart
            h.push(ev("Read", "response", who, ts));
            h.push(ev("Export", "request", who, ts + 300_000_000_000));
        }
        h
    }

    #[test]
    fn a_cached_history_holds_the_state_a_full_replay_builds() {
        for event_schema in [None, Some(UNPINNED_EVENT_SCHEMA)] {
            let h = longer_history();
            let mut cached = StatelessTemporalEngine::new(POLICY, SCHEMA, event_schema, None)
                .unwrap()
                .with_history_cache(4);
            let mut plain =
                StatelessTemporalEngine::new(POLICY, SCHEMA, event_schema, None).unwrap();
            for end in (1..h.len()).step_by(2) {
                let a = cached.decide_last(&h[..=end]).unwrap();
                let b = plain.decide_last(&h[..=end]).unwrap();
                assert_eq!(a.ts, b.ts, "{event_schema:?} ..={end}");
                assert_eq!(
                    a.response.allowed(),
                    b.response.allowed(),
                    "{event_schema:?} ..={end}"
                );
                assert_eq!(cached.cache.len(), 1, "one line, one entry");
                let entry = &cached.cache[0];
                assert_eq!(entry.events.as_slice(), &h[..=end]);
                assert_eq!(
                    entry.engine.save_snapshot(),
                    snapshot(&plain),
                    "{event_schema:?} ..={end}: replayed in parts == replayed at once"
                );
            }
            let stats = cached.history_cache_stats();
            assert_eq!(
                (stats.misses, stats.prefix_hits),
                (1, 11),
                "{event_schema:?}"
            );
            // The scratch engine was never used.
            assert!(!cached.dirty);
        }
    }

    #[test]
    fn a_poisoned_engine_keeps_the_history_cache() {
        let h = longer_history();
        let mut e = StatelessTemporalEngine::new(POLICY, SCHEMA, None, None)
            .unwrap()
            .with_history_cache(4);
        e.decide_last(&h[..=9]).unwrap();
        let shared = e.engine.clone();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            shared.with_mut(|_| panic!("poison the engine lock"));
        }));
        assert!(panic.is_err());
        assert!(e.engine.with(|_| ()).is_none(), "lock was not poisoned");

        let got = e.decide_last(&h[..=11]).unwrap();
        let expected = StatelessTemporalEngine::new(POLICY, SCHEMA, None, None)
            .unwrap()
            .decide_last(&h[..=11])
            .unwrap();
        assert_eq!(got.ts, expected.ts);
        assert_eq!(got.response.allowed(), expected.response.allowed());
        let stats = e.history_cache_stats();
        assert_eq!((stats.misses, stats.prefix_hits), (1, 1), "{stats:?}");
        assert_eq!(stats.calls, 2, "counters survive the rebuild");
        assert!(
            e.engine.with(|_| ()).is_some(),
            "rebuilt with a healthy lock"
        );
    }

    #[test]
    fn a_refused_extension_leaves_the_cached_history_intact() {
        let h = longer_history();
        let mut e = StatelessTemporalEngine::new(POLICY, SCHEMA, None, None)
            .unwrap()
            .with_history_cache(1);
        e.decide_last(&h[..=9]).unwrap();
        let mut backwards = h[..=9].to_vec();
        backwards.push(ev("Export", "request", "alice", T0)); // before history[9]
        let refused = e.decide_last(&backwards).unwrap_err();
        assert!(
            refused.to_string().contains("history[10] timestamp"),
            "{refused}"
        );
        assert_eq!(e.cache.len(), 1);
        assert_eq!(e.cache[0].events.as_slice(), &h[..=9]);

        let before = e.history_cache_stats();
        e.decide_last(&h[..=11]).unwrap();
        let after = e.history_cache_stats();
        assert_eq!(after.prefix_hits - before.prefix_hits, 1);
        assert_eq!(after.replayed_events - before.replayed_events, 2);
    }

    #[test]
    fn lowering_the_capacity_keeps_the_most_recent_histories() {
        let h = longer_history();
        let mut e = StatelessTemporalEngine::new(POLICY, SCHEMA, None, None)
            .unwrap()
            .with_history_cache(3);
        // Three histories that share nothing: each starts at a different event.
        let (a, b, c) = (&h[0..=1], &h[2..=3], &h[4..=5]);
        for history in [a, b, c, a] {
            e.decide_last(history).unwrap();
        }
        assert_eq!(e.cache.len(), 3);
        let e = e.with_history_cache(2); // drops b, the least recently used
        let mut kept: Vec<&[Event]> = e.cache.iter().map(|x| x.events.as_slice()).collect();
        kept.sort_by_key(|events| events[0].timestamp());
        assert_eq!(kept, [a, c]);
    }
}
