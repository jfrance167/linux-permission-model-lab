# Frozen contract — October 5, before code

API accepts exact built-in dict root/subject/node objects and exact built-in list
ancestors/groups/features. No subclasses/custom iteration/coercion. Root keys:
version, profile, unsupported_features, subject, ancestors, target, operation.
Version exact int 1; other nonnegative ints <=999999999 unsupported versions.
Profile exact visible-ASCII identifier <=32 characters; ordinary_dac_v1 supported,
other valid identifiers unsupported. All other unknown/missing keys rejected.

Subject exact keys fsuid/fsgid/supplementary_gids; exact integer IDs 0–999999999,
Boolean rejected, 0–16 supplementary IDs, duplicates rejected. fsuid0 unsupported;
fsgid0 ordinary matching group only. No database/identity lookup or effective-ID
inference. Node keys id/kind/owner_uid/group_gid/mode. ID matches [A-Za-z][A-Za-z0-9_-]{0,31}.
kind regular/directory; other kinds rejected, symlink contexts declared as features.
Mode exact str [0-7]{4}; 0000–0777 supported, special-bit modes unsupported.
Ancestors 1–8 directory records, unique IDs across all ancestors+target.

Features 0–16 unique exact string IDs in fixed set acl, capabilities, lsm, mount,
idmap, namespace, symlink, race, sticky, setid, immutable, append_only,
open_descriptor. Unknown features rejected; any present known feature unsupported.
Empty features/profile assert the synthetic subset, not real absence of features.

Operations file_read=4, file_write=2, file_read_write=6, file_execute_bit=1 on
regular targets; directory_search=1 and directory_list_names=4 on directories.
Mismatched supported operation/kind rejected. create/delete/rename are known
unsupported operations; other operations rejected. No creation-mask feature.

Validate every record before semantic outcomes. Invalid field/type/range/shape,
duplicate or kind mismatch yields rejected (limits yield over_limit) before any
unsupported context or permission result. Unsupported reasons collect/sort profile,
version, root, special_mode, each feature, operation. No partial permission checks
emitted for invalid/unsupported requests. All semantic fields validated even if
an earlier ancestor lacks search or fsuid0/features are supplied.

Class: owner iff fsuid==owner_uid, else group iff group_gid==fsgid or in supplied
supplementary list, else other. Bits: (mode>>6)&7, (mode>>3)&7 or mode&7 respectively.
Predicate requires (present & required)==required, never any-bit/union/fallback.
Each ancestor independently requires bit1; target its operation mask. Report all
per-record checks in order, including target independently of failed ancestors.
model_permits is all ancestor predicates AND target predicate; actual_access
always unverified. Name-read is a pure bit4 predicate, not a syscall success.

Bounds: exact raw bytes <=16384 before strict UTF-8/JSON parsing; nesting<=6
outside strings, numeric token<=10 chars including sign; floats/constants rejected.
API matches semantic ranges/cardinality/text. IDs and enum strings ASCII only;
surrogates/controls rejected through strict allowlists. Duplicate JSON keys rejected.
No path grammar, file/OS calls, Unicode normalization or silently masked special bits.

Report status model_complete/rejected/unsupported/over_limit, complete Boolean,
reason, actual_access='unverified', fixed assumptions/not_verified. Unsupported
adds fixed sorted reasons only. Complete adds model_permits, ancestor_checks and
target_check (ID/class/present/required/predicate). Output ensure_ascii=True,
allow_nan=False compact JSON+LF <=65536 bytes; oversize becomes incomplete output_limit.
Formatter accepts internally constructed reports only. No atomic stdout claim.
CLI exits 0 model permits/passing demo, 1 model denies/failed demo, 2 invalid/
unsupported/over-limit, 3 I/O failure. Failed/short write/flush may leave partial
output, never success. Error stderr fixed JSON, no input/exception details.

Independent examples in PLAN.md are fixed before implementation. Fixtures must
hard-code expected selected class/present/required/target/overall and ancestor
outcomes, not compute expectations with the model. Tests check hand-derived
owner0044 denial, matching-group0004 denial, supplementary0040 grant, other0004
grant, read_write0400 denial, ancestor0600 search denial, directory0400 name-read
without search, directory0100 search without name-read, regular0200 write under
0100 ancestor without parent-write requirement, fsgid0 matching-group (no bypass),
root/special-feature unsupported and later-malformed precedence.
