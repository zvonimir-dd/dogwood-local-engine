# Dogwood Local Engine — Release Notes

Release notes for the Dogwood local authorization engine
(`dogwood-local-engine`, `dogwood-server`, `dogwood-performance`).


## [Unreleased]

### Summary

Stateless decisions: given a whole event history, decide its last event with
the verdict a fresh store's `submit` would give, without a store, a log or a
clock, and keep nothing afterwards.

### Compatibility

- `install`, `submit` and recovery are unchanged. The compile step they use
  moved into a private function that the stateless engine shares; its error
  order and messages are the same.
- Same `dogwood-language` revision. The additions are new API only.

### Added

- **engine**: `StatelessTemporalEngine` (`new`, `decide_last`, `status`,
  `list`), `Decided`, and the one-shot `decide_last`. A policy set compiles
  exactly when `install` would accept it, with the same message when it does not.
  History timestamps are epoch nanoseconds; ties are spread like `submit`'s
  clamp; a decreasing timestamp or a history ending in a non-decision event is a
  `BadEvent`. Attribution tokens are placeholders (`SPref<n>`).
- **server**: `dogwood-server decide-last POLICY --action-schema F --events F|-`,
  in-process with no server. The history is JSON Lines of `{"ts", "event"}` or a
  JSON array; `--json` and `--timings` are available; exit codes match `submit`.
- **performance**: the `stateless_decide` benchmark and the `stateless_diff`
  differential and latency harness. `--merge K,…` interleaves corpus
  trajectories into multi-session histories and checks each member's outcomes
  are the ones it has alone (isolation under the principal pin).

---

## [1.1.0] — 2026-10-09

### Summary

This release teaches the engine to evaluate arithmetic in temporal comparison
operands, matching the new `Term::Arith` in dogwood-language. The capability is
experimental and opt-in — a default build rejects arithmetic policies at the
frontend — so most consumers upgrade with no behavioral change.

### Compatibility

- **dogwood-language**: Pairs with the dogwood-language v1.1.0 that adds
  `Term::Arith` and the `experimental-arithmetic` feature. The engine's own
  `experimental-arithmetic` feature forwards to the frontend's.

### Experimental

These are non-official, opt-in features. Their syntax and behavior may change
or be removed in a future release, and they are off by default.

- **monitor**: Evaluation of arithmetic comparison operands. `Operand` grows an
  `Arith` variant built recursively from `Term::Arith`; values are per-operation
  saturating `i64` in tree order, matching the reference `resolve_term_at`. An
  atom that does not resolve to an integer falsifies the enclosing comparison,
  and a compound side never binds. Aggregates inside arithmetic stay
  `Operand::Agg` leaves, so memoization, history recording, and snapshot walks
  apply unchanged. The feature is gated behind the off-by-default
  `experimental-arithmetic` Cargo feature, which forwards to the frontend's; the
  evaluator stays compiled either way, and a feature-off frontend rejects
  arithmetic before it reaches `prepare`.

---

