# Decisions — October 5, 2026

- Build a small standard-library arithmetic model; kernel source is the semantics
  reference, PyFilesystem a bit container, LTP a real-syscall test suite. None fits
  this bounded invented-record lab as a dependency. No upstream code copied.
- Select ordinary existing-node permission bits, rather than umask creation rules.
  Creation/default ACL/inheritance semantics need a different contract.
- Explicit filesystem identity and declared exclusions avoid conflating `access(2)`
  real IDs with actual filesystem lookup identity. fsuid0 unsupported; fsgid0 normal.
- Owner wins even without requested bits. Group wins over other if membership
  matches. All requested bits must exist within that single selected triplet.
- Search each supplied ancestor independently, then check target separately. A
  directory name-read predicate does not prove name lookup or a successful syscall.
- Validate all records before semantic denial/unsupported; invalid data cannot be
  hidden by earlier denied/root/special-mode/context records.
- Exact built-in types and finite grammar/ranges/cardinality; no coercion or
  normalization of ambiguous fields. Oversized strings fail length guards before
  regex processing. Numeric/depth/raw bounds are application controls, not isolation.
- Runtime has zero third-party dependencies. Reviewed development workflow reused
  locally; scanners pinned by version, artifact hash lock still unavailable.
- No remote worker with unverified free guardrails; local idea draft rejected.
  Codex retains source interpretation, implementation and ECC self-review.
