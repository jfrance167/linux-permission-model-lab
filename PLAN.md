# Proposed Linux ordinary-permission model — October 5, 2026

Tier 3 security learning, stages 1–3 approved October 5, 01:51 Eastern by
coordinator under Jake's verified mandate. Approval/addendum recorded before code.
Source/reuse/adoption assessment in RESEARCH.md. Sole
writer same chat/directory; cutoff October 6, 08:00 Eastern. No changes to earlier
projects/parent/shared tools, host permissions/identity/filesystem, real users/paths,
live Linux/shell/container/VM execution, publication/merge/new chat/scheduler/spending.

## Problem and success

Show exact ordinary owner/group/other selection without union/fallback, and why
supplied ancestor-directory search checks differ from final file read/write/execute
bits and directory listing. Success: a bounded invented-record request produces
the selected class, required/present bits and each relevant search check, with an
explicit subset result. No actual-access or path-containment verdict.

Build original standard-library integer model instead of adopting broad filesystem
libraries/kernel/LTP code. Alternative creation-mask/default-mode calculation is
researched but excluded from implementation. Existing web RBAC/admin/owner shortcuts
must not be reused as Linux class rules. No runtime dependencies proposed.

## Scope and proposed contract (freeze precisely in stage 1)

- Strict versioned UTF-8 JSON on stdin and reusable pure API, supplied invented
  subject, ordered ancestor records, target record and operation. Exact built-in
  containers/strings/integers, no arbitrary iteration/coercion/host lookup.
- Subject fields: invented fsuid/fsgid and bounded supplementary-gid list. IDs
  exact nonnegative integers within a fixed finite range, Booleans rejected.
  fsuid 0 unsupported, never auto-granted. Owner/group IDs describe supplied
  object metadata, not accounts looked up on this host.
- Object fields: fixed synthetic visible-ASCII ID (no slash/backslash/dot path
  grammar), kind regular/directory, owner_uid/group_gid and exact four-octal-digit
  mode. Ordinary 0000–0777 supported; special bits well-formed but unsupported.
  One to eight supplied ancestor directory records; no graph, resolver, real path,
  symlink or existence inference. Validate all records before returning results.
- Required explicit `profile: ordinary_dac_v1` and empty `unsupported_features`
  list. Known exclusions present in that list return unsupported; unknown values
  rejected. This is a caller-declared synthetic assumption, not proof those
  features are absent. Freeze known feature IDs and conflict/duplicate policy.
- Supported regular operations: file_read (4), file_write (2), file_read_write
  (6), file_execute_bit (1). Execute means a mode-bit predicate only, no program
  execution/format/interpreter/noexec-mount check. Directory operations:
  directory_search (1), directory_list_names (4). Listing names does not assert
  child stat/lookup ability; no final search requirement added to pure name-read
  predicate. Every supplied ancestor still needs its own selected search bit.
- Choose owner if fsuid equals owner_uid; else group if group_gid equals fsgid
  or any supplementary gid; else other. Select exactly that triplet. Required
  bits must all be present. Failure never falls back to a different class.
- Preserve full per-record bit explanations. Overall `model_permits` depends on
  all ancestor search predicates and the target predicate within declared scope;
  actual_access always unverified. Unsupported/rejected/over-limit inputs have no
  completed permission result. No safe-path/system-safe Boolean.
- Creation, deletion/unlink, rename, ACL/sticky/setid/root/capability/LSM/mount/
  namespace/idmap/symlink/race/immutable/append-only/existing-descriptor behavior
  explicitly unsupported; do not derive them from target file write or bypass flags.

Proposed bounds: 16 KiB raw JSON before parse, nesting depth 6, numeric tokens at
most 10 characters, 16 supplementary gids, 8 ancestor records, 32-character IDs,
64 KiB final escaped JSON including newline. API enforces the same semantic
cardinality/type/range/string bounds. Duplicate/unknown keys, floats/constants,
malformed Unicode and control IDs rejected. Record/group duplicates should be
rejected for an unambiguous teaching contract. No prefix acceptance/truncation.
Short/broken writes fail nonzero without atomic-stdout promise. Exact schema,
status/exit map/ID range and unsupported precedence fixed before source code.

## Independently justified examples to freeze as test oracles

All IDs/nodes below invented; ancestors not otherwise stated give the selected
class search. Values in octal; outputs are subset predicates only.

| Example | Expected selected class and model result |
|---|---|
| Subject fsuid 101 owns regular target 0044; requests read | Owner 0; denied even though group/other have read |
| Nonowner fsuid 202, fsgid 10 matches target gid 10, mode 0004; read | Group 0; denied, no other fallback |
| Nonowner primary gid 20, supplementary [10], target gid 10/mode 0040; read | Group 4; permitted within subset |
| No owner/group match, target 0004; read | Other 4; permitted within subset |
| Owner target 0400; read_write | Owner 4 lacks write; denied, do not split request across classes |
| Owner-readable target 0400 under owner ancestor 0600 | Ancestor search denied; target read still true independently |
| Owner directory 0400 | Name-read predicate true, search false; no child-metadata guarantee |
| Owner directory 0100 | Search true, names-read false |
| Owner file target 0200 under searchable ancestor 0100 | File-write predicate true despite no parent write; no creation/deletion claim |
| Supplied fsuid 0, special-bit mode or ACL/sticky context | Unsupported, no ordinary success verdict |

Freeze canonical JSON expectations and hand-calculated triplet extraction, record
order/IDs/reasons before code. A hypothetical incorrect union/fallback model must
be caught by the first two examples; dropping ancestor checks by the sixth.

## Architecture, threat model, risks

Bounded invented JSON → strict schema/context validation → fixed class selection
and per-record integer bit checks → supplied-chain aggregation → bounded escaped
report. No operating-system identity/access/stat/traversal/permission/mask calls.

Attacker controls request text and supplied assumptions. Protect report integrity,
bounded computation and host isolation by removing filesystem/privilege capability,
validating exact concrete types, fixed operations/IDs/ranges, rejecting unsupported
context and avoiding claims beyond the subset. Runtime and reviewed source trusted;
host filesystem sandbox is not a malware-isolation boundary.

Supplied chain/context may be incomplete or false about any real system. Mode bits
cannot prove actual access, object existence, path containment or full Linux/POSIX
authorization. Not access(2), open(2) or filesystem execution emulation. Kernel
optimized/more complex logic is a reference, not copied. Additional permissions,
exceptions and races remain explicit exclusions, not silently ordinary checks.

## Stages and definition of done

1. Freeze contract/source-linked independent fixtures; implement reusable pure
   bounded selector and supplied-search-chain model. Done: owner/group/other
   precedence, no union/fallback, every requested bit checked, context unsupported
   before success and exact expectations fixed separately from implementation.
2. CLI/demo and synthetic regressions. Done: all examples pass, invalid/unsupported/
   boundary/one-over cases explicit, all-record validation before outcomes, API
   mutation/input-coercion resistance, deterministic escaped output/I/O failures,
   forbidden OS/identity/permission/stat/traversal/process/network guards.
3. ECC actual-code self-review, focused class/ancestor mutations, normal/optimized
   tests, available SAST and local pinned workflow baseline. Done: exact evidence,
   README/setup/demo/threat model/limitations/license/AI assistance, STATE/DECISIONS/
   LEARNING and authorized Obsidian milestone. No hosted/actual-Linux claim.

Tests: primary/supplementary group and owner precedence, every triplet/operation,
all-bits versus any-bit, search/list separation, chain failures/order, malformed
ID/mode/kind/operation/context, root/special bits/feature exclusions, duplicate IDs/
gids/JSON keys, Booleans/floats/numeric/depth/raw-byte/output bounds, exact report
expectations, immutable input and error channels. Only inert records; no test may
chmod/chown/access/stat/umask/getuid/walk/resolve, launch a shell or contact a host.

Local-first idea draft rejected for source-conflicting suggestions (RESEARCH.md).
No remote inference with unverified guardrails and no paid fallback. Coordinator
approval is recorded; proceed through the three approved local stages.

## Mandatory approval addendum (recorded before code)

SUCCESSORS.md Linux permission implementation approval — October 5, 01:51
heartbeat: freeze finite ID/mode/profile/features/operation-kind/duplicate and
invalid-versus-unsupported rules (CONTRACT.md); validate every field/record before
denial or unsupported so later malformed metadata cannot hide behind an early
denial/root/feature. Duplicate IDs across chain+target and supplementary IDs
rejected. fsgid 0 alone is not root/bypass. Keep one triplet/all requested bits,
ancestors and target predicates separate; name-read is a model predicate only.
No OS calls in model/analyzed input. Trusted harness may read own source/write
evidence, without live permission experiments. Bounds, honest I/O, fixed fixtures,
mutations, normal/optimized tests, ECC/SAST/docs/vault remain required.
