# Security policy

This is a local educational model. No input can authorize access, run a command,
change permissions or prove real-world syscall success. Use invented non-sensitive
records only. Empty excluded-feature declarations are caller assumptions.

Trust boundaries: untrusted JSON/API records -> strict bounded schema -> pure bit
predicates -> escaped report. Trusted fixture/test/tool code is separate; the
harness reads its own configuration and writes evidence. A Python environment is
not a malware sandbox. Do not feed generated executable code to this model.

Threats covered: duplicate/unknown keys, malformed identity/mode/kind/context,
custom-object coercion, bounded JSON resource use, owner/group fallback and
missing ancestor search checks, unsupported context falsely appearing complete,
misleading I/O success. Output failure may leave partial bytes and returns exit 3.

Excluded: real identity/metadata truth, host access decisions, path containment,
ACL/capability/LSM policy, mount/namespaces/idmapping, symlink resolution, races,
creation/deletion/rename, special bits and inherited descriptor access. These are
explicit limits, not proof that they are absent in a real filesystem.

For a defect, preserve an invented minimal JSON example, observed status/exit,
Python version and source revision. Contact the owner through an agreed private
channel; no public reporting endpoint or response SLA is configured. Never include
credentials, employer/client data or real private filesystem records.
