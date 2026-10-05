# Linux permission model research — October 5, 2026

Research/planning only. Read current coordinator scope, vault Home/Codex Integration
and Linux File Modes and Directory Access reference; notes are retrieval evidence,
not new operational authorization. No host permission checks or Linux execution.

## Local reuse and candidates

Read container-security-hardening-lab README and relevant analyzer declarations:
it checks container settings/capability declarations, not permission-class selection.
Read web-access-control-security-lab README and source around identity/RBAC/tenant
checks: its fixed-role/owner logic differs from Linux mode-class behavior. Reuse
invented fixtures, bounded-report and source-linked test concepts, not its admin
or owner-bypass policy. Earlier CSV lab's strict JSON/output patterns and pinned
workflow checker may be reused after approval, without modifying those projects.

Bounded vault keyword/filename searches found the supplied Linux reference and
study index, not a matching implementation. Local permission/umask filename search
excluding private/vendor/environment/Git/GLPI areas identified no dedicated matching
lab. Limited searches do not establish an exhaustive inventory.

| Candidate | Learning | Scope tradeoff |
|---|---|---|
| Ordinary DAC class and supplied directory search | Select exactly one mode triplet, filesystem identity/supplementary groups, independent directory/file checks | Must exclude richer Linux contexts and actual path lookup |
| Offline creation-mask/default-mode interpretation | Requested mode versus masked result, file/directory defaults are supplied by caller | Default ACL/SGID inheritance and application choices complicate any default claim |

Recommend build the ordinary-mode model first. Creation masking is an alternate,
not an additional implemented feature. This avoids conflating existing-file access
with permission bits assigned at creation.

## Primary Linux findings

[path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html)
describes nonfinal-directory search and ordered owner/group/other selection, and
clarifies Linux filesystem UID/GID rather than assuming effective IDs always equal
them. [credentials(7)](https://man7.org/linux/man-pages/man7/credentials.7.html) and
[kernel credentials](https://www.kernel.org/doc/html/latest/security/credentials.html)
supply process-context background. The lab accepts invented fsuid/fsgid/group
records; it never queries identity or maps actual namespaces.

[access(2)](https://man7.org/linux/man-pages/man2/access.2.html) uses real IDs in its
ordinary form and can differ from operation checks. Do not call os.access or label
this offline model a simulation of that syscall. [inode(7)](https://man7.org/linux/man-pages/man7/inode.7.html)
documents read/write/execute triplets, directory search and special bits. Directory
name listing differs from known-name lookup and child metadata; ordinary final-file
read/write bits do not replace ancestor search checks.

[unlink(2)](https://man7.org/linux/man-pages/man2/unlink.2.html) and
[rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html) document parent-directory
write/search checks, sticky/other restrictions and additional failure conditions.
Deletion/rename/creation are not the same as writing file contents; the first lab
will return unsupported for them rather than derive access from target-file write.

[umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html) supports the alternate
`requested_mode & ~mask & 0777` ordinary calculation, with a different default-ACL
path. [mkdir(2)](https://man7.org/linux/man-pages/man2/mkdir.2.html) also documents
directory creation/SGID considerations. Never read/set the host umask or claim
0666/0777 is every application's requested mode. Example arithmetic only:
supplied requested 0666/mask 0022 → 0644; 0777/0027 → 0750. Default ACL or SGID
context would be unsupported in that alternate.

## Actual implementation and test inspection

Connected GitHub search initially failed transport; direct source calls then
succeeded. The integration was used rather than implying missing access. No
upstream package/kernel/test was installed, compiled or executed.

**[Linux namei.c](https://github.com/torvalds/linux/blob/master/fs/namei.c)**:
actual `acl_permission_check`/`generic_permission` excerpts inspected, blob
`20a6534ea3efffd6686e3b49c3e76f399c966f9e`. Owner comparison uses current_fsuid;
matching owner returns its triplet result without group/other fallback. Group
membership chooses group bits; permission request bits must all be present.
The optimized group comparison can skip membership when relevant group/other bits
are identical; it is not a union rule. ACL, idmapped mounts, filesystem-specific
permission methods and DAC capabilities make this much broader than our model.
Recent namei history observed commit `1c3e8cef79ea5f1415cff0d3c507e2e07b71ade8`,
August 17, 2026 (VFS merge/maintenance), not an immutable branch snapshot for all
fetched files. File SPDX GPL-2.0 and COPYING GPL-2.0 with syscall-note inspected.
Do not copy kernel code into an MIT lab; implement documented bit arithmetic
originally. Kernel build/security posture cannot be established by these excerpts.

**[PyFilesystem2](https://github.com/PyFilesystem/pyfilesystem2)**:
inspected actual [Permissions](https://github.com/PyFilesystem/pyfilesystem2/blob/master/fs/permissions.py),
[tests](https://github.com/PyFilesystem/pyfilesystem2/blob/master/tests/test_permissions.py),
MIT LICENSE, setup.py/setup.cfg and CI. Source blob
`3fee3352e226fc932eff9d1ce73b75e022b2e299`, test blob
`72e5f197ada73f5caf7adb8be3eae40430cb4b7d`. It represents named/mode bits, supports
special-bit representation and tests parsing/setting/serialization. Its check
method tests a supplied permission-name set; it is not a process-identity/path
authorization model. Broad filesystem abstraction includes capabilities outside
this lab. Runtime dependencies include appdirs/setuptools/six and legacy backports;
none needed for a small integer model. Latest observed repository commit
`77a8562785fc37cb2e30bdcd39c133097ba62dce`, May 17, 2025, changes a docs link;
previous returned commit October 2022. This sparse observed activity is a maintenance
concern, not proof of abandonment/insecurity. CI includes older Python versions,
mutable Actions and upgraded tools; do not copy its security baseline. Narrow
permission-title issue search returned closed [ZIP mode preservation issue 60](https://github.com/PyFilesystem/pyfilesystem2/issues/60),
which concerns backend behavior, not ordinary class selection. No relevant identity
model defect established; no upstream tests rerun, exhaustive issue/security audit
or Scorecard claim. If borrowing code later, retain MIT attribution/license.

**[LTP](https://github.com/linux-test-project/ltp)**:
inspected [faccessat01.c](https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/syscalls/faccessat/faccessat01.c),
blob `2c54fe2bd15fc3a6e8bb806887703f9b2c0d4b16`, GPL-2.0-or-later header. It uses
actual file creation/directory descriptors and syscall checks through the LTP test
harness; it is not a pure permission oracle and is outside execution authorization.
Latest repository activity observed October 1, 2026, commit
`dca9f0d272b2923256852fc37abd222b533d91e0` (compiler-warning fix). Full dependency/
CI/security posture not assessed. No borrowing/running; source comparison only.

Recommendation: original standard-library model. Neither broad PyFilesystem nor
kernel/LTP adoption matches bounded invented records without host operations.
Maintain links/credit; no third-party code copied or dependency installation.

## Local-first record and uncertainties

One local Ollama idea draft completed: 330-token cap, 30-second timeout, actual
215 output tokens/~8.2 seconds. Rejected nonexistent-ID/group-check assumptions
and wording implying real file creation/skipping ancestor checks. In an invented
record model there is no account database lookup. No generated code executed.
OpenRouter considered but readiness degraded/guardrails unverified; refreshing
would write excluded shared tooling. No remote/paid fallback or retry loop.

Remaining uncertainties are deliberately excluded: ACL/root/capabilities, LSM,
special bits/sticky, mount/namespace/idmapping, immutable/append-only state,
symlinks/hardlinks, races/existence, already-open descriptors and full syscall
semantics. Supplied assumptions are not verified facts about a system. No actual
Linux outcome or path-containment guarantee follows from a model result.
