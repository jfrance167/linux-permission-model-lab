# Learning — October 5, 2026

Mode bits select a class before checking the request. An owner of `0044` sees the
zero owner triplet, not the readable group/other triplets. Group membership includes
the supplied primary filesystem group and supplementary groups; group zero is not
root. `read_write` needs both 4 and 2 in the same triplet.

Directory search (1) and names-read (4) are different predicates. A target may have
read permission while an ancestor prevents modeled traversal. Writing an existing
file does not itself require parent write; creating/deleting/renaming are excluded.

Synthetic calculations cannot validate supplied records or replace Linux policy.
Actual filesystem identity, ACLs, capability override, LSM, mounts and races make
real access wider than this arithmetic subset. Root and special contexts remain
unsupported rather than acquiring simplified bypass rules.

Independent fixed expectations caught deliberately unioned classes and omitted
ancestor checks. Two caught mutations establish those specific regressions only,
not broad accuracy or fault coverage. The first test-discovery command used the
parent directory and failed to discover tests; rerunning from this lab fixed the
harness invocation, without changing application behavior.

The local 2B ideas draft suggested invalid assumptions about nonexistent accounts
and supplementary groups. Source review rejected them. A plausible model draft
does not become a security requirement or an approval.
