# Linux permission model lab

A dependency-free Python learning tool for **invented ordinary Linux mode records**.
It explains owner/group/other selection, required permission bits, and independent
search checks on supplied ancestor directories. Every report says actual access
is **unverified**. It is not an authorization service or a host permission checker.

## Run

Use Python 3.13, from this directory. Application code uses only the standard library.

```powershell
python -m permission_lab demo
python -m unittest discover -s tests -v
python -O -m unittest discover -s tests -v
python tools/check_mutations.py
```

The demo contains eleven hand-fixed examples. One explains why an owner of a
`0044` file gets zero owner bits even though group/other can read. Another shows
that an otherwise readable target fails the model when an ancestor lacks search.
See [evidence/demo.json](evidence/demo.json) for actual captured reports.

For an invented JSON request, pipe its UTF-8 bytes to `python -m permission_lab analyze`:

```json
{"version":1,"profile":"ordinary_dac_v1","unsupported_features":[],"subject":{"fsuid":101,"fsgid":20,"supplementary_gids":[]},"ancestors":[{"id":"Parent","kind":"directory","owner_uid":101,"group_gid":10,"mode":"0100"}],"target":{"id":"Target","kind":"regular","owner_uid":101,"group_gid":10,"mode":"0044"},"operation":"file_read"}
```

This returns `model_complete`, target owner bits `0`, required bits `4`, and
`model_permits: false`. CLI exit codes: 0 model permits/passing demo, 1 model
denies/failing demo, 2 incomplete request, 3 input/output failure. A failed output
write can leave partial bytes; do not accept a partial report or an unsuccessful exit.

## Architecture and API

`permission_lab/core.py` validates all fields, selects exactly one class, checks
each ancestor for search, then checks the target operation. CLI reads at most
16 KiB plus one detection byte; reports are escaped JSON capped at 64 KiB.
The pure model has no filesystem, identity, permission, process or network imports.
`fixtures.py` holds invented records and independent expected values. Tests and
tools are trusted harness code and may inspect their own sources/configuration.

- `evaluate(request)` accepts exact built-in dictionaries/lists under
  [CONTRACT.md](CONTRACT.md); it never mutates the request.
- `analyze_json(raw)` accepts exact UTF-8 bytes, rejects duplicate keys and imposes
  byte/depth/numeric limits before model evaluation.
- `serialize_report(report)` formats internally constructed reports only.

Read [CONTRACT.md](CONTRACT.md) for the schema, bounds and status precedence.
Unknown or malformed values reject; declared ACL/capability/LSM and other excluded
contexts, root fsuid, special mode bits and creation/deletion/rename are unsupported.
Group ID zero has ordinary group matching semantics and no bypass.

## Security model and limits

The threat is misleading or malformed supplied metadata yielding an apparently
complete decision. Strict types, bounded parsing and validation before semantic
outcomes prevent malformed later records from hiding behind an early denial or
unsupported context. Exact one-class/all-bits predicates avoid fallback/union errors.
These controls do not establish that a caller's records describe a real system.

No lookup of users, paths, permissions or file contents occurs. Filesystem identity
is explicitly supplied `fsuid`/`fsgid`, not inferred real/effective process IDs.
No real Linux calls, ACLs, capabilities, mount policy, LSM, namespaces, symlinks,
idmapped mounts, descriptor access or races are modeled. Directory name-read and
execute-bit checks are arithmetic predicates, not syscall guarantees. The caller
must never use `model_permits` as authority to access a real resource. See
[SECURITY.md](SECURITY.md), [PLAN.md](PLAN.md) and [RESEARCH.md](RESEARCH.md).

## Verification and portfolio status

Verified locally on Windows, CPython 3.13.7: 21 tests in normal and optimized mode,
eleven demo expectations, two detected/restored in-memory defects, Bandit zero
findings, workflow-policy checks in normal/optimized mode and `pip check`.
[VERIFICATION.md](VERIFICATION.md) records commands, evidence and limits.

Prepared CI runs Python 3.13 on Windows/Ubuntu, Bandit, and weekly/manual CodeQL.
Every Action uses a reviewed immutable SHA and minimal permissions. This local
repository has no remote: hosted CI/CodeQL, GitHub eligibility/protections and
Linux runtime behavior have not been verified. Security-tool versions are pinned,
but an artifact hash lock and dedicated secret scan remain unavailable.

MIT licensed. No Linux/LTP/PyFilesystem code copied; source references and license
assessments are in RESEARCH.md. CLI test/workflow infrastructure was adapted from
Jake's prior local CSV lab. Codex authored and reviewed the implementation; a local
Ollama ideas draft was rejected. No remote inference or paid fallback was used.
This was an ECC checklist **self-review**, not independent review.

Learning: [LEARNING.md](LEARNING.md). Decisions: [DECISIONS.md](DECISIONS.md).

Optional exercise: explain why `0044` fails for the owner but can pass for a
nonowner outside the owning group, assuming searchable ancestors.

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
