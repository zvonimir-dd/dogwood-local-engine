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
//! There is no log, no clock and no durability, and nothing carries from one
//! call to the next. Compile once, decide many times: the compiled set is the
//! expensive part, and every call reuses it.

use std::borrow::Cow;
use std::fmt;

use dogwood_language::{Authorizer, Event, ServiceSchema, TemporalEngine};

use super::attribution::{RuleAttribution, attribute_response};
use super::{
    Compiled, DecisionResponse, DurableError, DurableTemporalEngine, Installed, Preparation,
    ServiceConfig, Status, assemble, checked_next_timestamp, compile, decision_without_response,
    reject_unresolved_transplant_origins,
};
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
/// The temporal state built for a call stays allocated until the next call
/// (which discards it first) or until the engine is dropped.
pub struct StatelessTemporalEngine {
    /// The compiled bundle, kept to rebuild the engine if its lock is poisoned.
    installed: Installed,
    service: ServiceSchema,
    authorizer: Authorizer,
    /// The temporal engine the authorizer reads, shared so it can be reset.
    engine: SharedEngine,
    attributions: Vec<RuleAttribution>,
    preparation: Preparation,
    status: Status,
    /// Whether the engine holds a previous call's state.
    dirty: bool,
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
        })
    }

    /// Decide the last event of `history`, given the events before it.
    ///
    /// `history` is in time order and its last event is of a decision kind
    /// ([`Status::decision_kinds`]); otherwise this is a
    /// [`DurableError::BadEvent`] and nothing is evaluated. A decision that cannot
    /// be evaluated (a missing attribute, say) is still `Ok`, as a deny with its
    /// errors, exactly as from `submit`.
    pub fn decide_last(&mut self, history: &[Event]) -> Result<Decided, DurableError> {
        let Some((last, earlier)) = history.split_last() else {
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
        // Before any observation: a partitioned engine requires time order.
        let stamps = stamp(history)?;

        self.reset()?;
        self.dirty = true;
        self.engine
            .with_mut(|engine| {
                for (event, &ts) in earlier.iter().zip(&stamps) {
                    engine.observe(&at(event, ts));
                }
            })
            .ok_or_else(poisoned)?;

        let ts = stamps[history.len() - 1];
        let last = at(last, ts);
        match self.authorizer.is_authorized(&last) {
            Some(response) => Ok(Decided {
                ts,
                response: attribute_response(&response, &self.attributions),
            }),
            None => Err(decision_without_response(&last)),
        }
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
    /// global or unused): the observable that pins partitioned mode.
    #[doc(hidden)]
    pub fn temporal_shard_count(&self) -> usize {
        self.engine.with(|e| e.shard_count()).unwrap_or(0)
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
            None => *self = Self::from_installed(self.installed.clone(), self.service.clone())?,
        }
        self.dirty = false;
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

/// The timestamp each event is evaluated at: its own, moved one nanosecond past
/// the previous one where they tie (`submit`'s `max(now, last + 1)`). A timestamp
/// lower than the one before it is refused rather than moved, because moving it
/// would shift its windows.
fn stamp(history: &[Event]) -> Result<Vec<i64>, DurableError> {
    let mut stamps: Vec<i64> = Vec::with_capacity(history.len());
    for (i, event) in history.iter().enumerate() {
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
        let assigned = checked_next_timestamp(stamps.last().copied(), given).ok_or_else(|| {
            DurableError::BadEvent(format!(
                "history[{i}] cannot be stamped: no timestamp follows {}",
                stamps.last().copied().unwrap_or(given)
            ))
        })?;
        stamps.push(assigned);
    }
    Ok(stamps)
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
}
