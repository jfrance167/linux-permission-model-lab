# Verification — October 5, 2026

Local Windows CPython 3.13.7. Commands run from this lab directory using the
installed Python313 interpreter; no live Linux permission experiments.

| Command/check | Observed result | Evidence |
|---|---|---|
| `python -m unittest discover -s tests -v` | 21 passed, exit 0 | evidence/tests.txt |
| `python -O -m unittest discover -s tests -v` | 21 passed, exit 0 | evidence/tests-optimized.txt |
| `python -m permission_lab demo` | 11 fixed expectations passed, exit 0 | evidence/demo.json |
| `python tools/check_mutations.py` | class-union and ancestor-omission faults caught; restored regressions pass, exit 0 | evidence/mutations.json |
| Actual stdin `python -m permission_lab analyze` | owner0044 model denial, exit 1; actual access unverified | evidence/cli-denial.json, cli-exit.json |
| `python -m bandit -r permission_lab tools -f json` | zero findings/errors, exit 0; 348 analyzed source lines | evidence/bandit.json |
| `python tools/verify_workflows.py` and `python -O tools/verify_workflows.py` | local YAML policy PASS, both exit 0 | evidence/workflows*.json |
| `python -m pip check` | no broken requirements, exit 0 | evidence/pip-check.txt |
| Bounded common credential patterns + manual content review | 24 source/config/evidence files, zero flagged files | evidence/content-review.json |

Exit summaries in evidence/functional-exits.json and security-exits.json; final
source SHA-256 bindings in evidence/source-hashes.json. Source hashes bind the
implementation reviewed here, not future modifications or an external attestation.

Meaningful test coverage: independent owner/group/other and supplementary-group
examples, owner precedence, all-required bits, ordinary group zero, execute-bit and
name-read predicate limitations, independent ancestor/target reports, later invalid
precedence despite denied/root/special/unsupported context, duplicates, exact types
and hostile coercion/key objects, semantic/raw/depth/numeric/output bounds, stable
JSON/direct equivalence, no mutation, model host-capability guards, CLI short/failed
read/write/flush and output-limit exit paths. The two mutation checks change memory
only and restore originals before rerunning fixed tests.

First discovery command was mistakenly invoked in the parent directory and failed
before tests ran; rerun from the lab passed. No application bug was inferred from
that harness error. Final checks above run after the explicit string length guards.

Workflow pins reused from the earlier same-day official-source-reviewed lab:
checkout v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1`, setup-python v7.0.0
`5fda3b95a4ea91299a34e894583c3862153e4b97`, CodeQL v4.38.2 peeled commit
`2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2`. Verifier checks fixed reviewed pins,
credential persistence, permissions, main-branch triggers and weekly CodeQL; it
does not contact GitHub or prove hosted execution. Development requirement versions
are copied from the reviewed prior lab; no installation, upgrades or spending here.

Limits: Windows-only execution; no Linux runtime comparison or complete POSIX/Linux
conformance. No hosted Actions/CodeQL, remote repository/security eligibility,
branch protections, dependency artifact hash lock, dedicated secret scanner or
exhaustive history scan. `pip check` tests compatibility, not advisory absence.
Bandit clean and ECC self-review do not prove the tool safe. No third-party source
executed, paid/remote inference, publication or merge. Previous AI/ZIP/CSV repositories
were read-checked clean and not changed.
