"""Pure supplied-record permission arithmetic with no OS access capability."""

import json
import re

MAX_INPUT_BYTES = 16_384
MAX_OUTPUT_BYTES = 65_536
MAX_DEPTH = 6
MAX_NUMERIC_CHARS = 10
MAX_ID = 999_999_999
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}", re.ASCII)
FEATURES = frozenset(("acl", "capabilities", "lsm", "mount", "idmap", "namespace",
                      "symlink", "race", "sticky", "setid", "immutable", "append_only", "open_descriptor"))
OPERATIONS = {"file_read": ("regular", 4), "file_write": ("regular", 2),
              "file_read_write": ("regular", 6), "file_execute_bit": ("regular", 1),
              "directory_search": ("directory", 1), "directory_list_names": ("directory", 4)}
UNSUPPORTED_OPERATIONS = frozenset(("create", "delete", "rename"))
ASSUMPTIONS = ("invented_filesystem_identity", "supplied_chain_only", "ordinary_mode_subset")
NOT_VERIFIED = ("actual_access", "path_containment", "existence", "complete_system_context", "syscall_success")


class _Invalid(ValueError):
    def __init__(self, reason: str, status: str = "rejected"):
        self.reason = reason
        self.status = status


def _outcome(status: str, reason: str) -> dict:
    return {"status": status, "complete": status == "model_complete", "reason": reason,
            "actual_access": "unverified", "assumptions": list(ASSUMPTIONS),
            "not_verified": list(NOT_VERIFIED)}


def _keys(value: object, expected: set[str]) -> dict:
    if type(value) is not dict or len(value) != len(expected):
        raise _Invalid("object_shape")
    # A built-in dict may still contain hostile custom key objects. Reject
    # their types before set/hash/equality work on the input keys.
    if any(type(key) is not str for key in value) or set(value) != expected:
        raise _Invalid("object_shape")
    return value


def _number(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_ID:
        raise _Invalid("id_or_version_range")
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or len(value) > 32 or IDENTIFIER.fullmatch(value) is None:
        raise _Invalid("identifier")
    return value


def _list(value: object, minimum: int, maximum: int) -> list:
    if type(value) is not list or len(value) < minimum:
        raise _Invalid("list_shape")
    if len(value) > maximum:
        raise _Invalid("list_limit", "over_limit")
    return value


def _node(value: object) -> tuple:
    node = _keys(value, {"id", "kind", "owner_uid", "group_gid", "mode"})
    node_id = _identifier(node["id"])
    kind = node["kind"]
    if type(kind) is not str or kind not in ("regular", "directory"):
        raise _Invalid("kind")
    uid, gid = _number(node["owner_uid"]), _number(node["group_gid"])
    mode = node["mode"]
    if type(mode) is not str or len(mode) != 4 or re.fullmatch(r"[0-7]{4}", mode, re.ASCII) is None:
        raise _Invalid("mode_grammar")
    return node_id, kind, uid, gid, int(mode, 8)


def _validated(request: object) -> tuple:
    envelope = _keys(request, {"version", "profile", "unsupported_features", "subject",
                               "ancestors", "target", "operation"})
    version = _number(envelope["version"])
    profile = _identifier(envelope["profile"])
    features = tuple(_identifier(item) for item in _list(envelope["unsupported_features"], 0, 16))
    if len(set(features)) != len(features) or any(item not in FEATURES for item in features):
        raise _Invalid("feature_shape")
    subject = _keys(envelope["subject"], {"fsuid", "fsgid", "supplementary_gids"})
    uid, gid = _number(subject["fsuid"]), _number(subject["fsgid"])
    groups = tuple(_number(item) for item in _list(subject["supplementary_gids"], 0, 16))
    if len(set(groups)) != len(groups):
        raise _Invalid("duplicate_group")
    ancestors = tuple(_node(item) for item in _list(envelope["ancestors"], 1, 8))
    target = _node(envelope["target"])
    if any(node[1] != "directory" for node in ancestors):
        raise _Invalid("ancestor_kind")
    ids = [node[0] for node in ancestors] + [target[0]]
    if len(set(ids)) != len(ids):
        raise _Invalid("duplicate_node")
    operation = _identifier(envelope["operation"])
    if operation not in OPERATIONS and operation not in UNSUPPORTED_OPERATIONS:
        raise _Invalid("operation")
    if operation in OPERATIONS and OPERATIONS[operation][0] != target[1]:
        raise _Invalid("operation_kind_mismatch")
    # Only after every supplied field is validated can unsupported context or
    # permission denial be decided. No later invalid node is hidden by root.
    unsupported = set(features)
    if version != 1:
        unsupported.add("version")
    if profile != "ordinary_dac_v1":
        unsupported.add("profile")
    if uid == 0:
        unsupported.add("root")
    if any(node[4] & ~0o777 for node in ancestors + (target,)):
        unsupported.add("special_mode")
    if operation in UNSUPPORTED_OPERATIONS:
        unsupported.add("operation")
    return (uid, gid, groups), ancestors, target, operation, sorted(unsupported)


def _selected(subject: tuple, node: tuple) -> tuple[str, int]:
    uid, gid, groups = subject
    _, _, owner, owning_group, mode = node
    if uid == owner:
        return "owner", (mode >> 6) & 7
    if owning_group == gid or owning_group in groups:
        return "group", (mode >> 3) & 7
    return "other", mode & 7


def _check(subject: tuple, node: tuple, required: int) -> dict:
    selected, present = _selected(subject, node)
    return {"id": node[0], "selected_class": selected, "present_bits": present,
            "required_bits": required, "predicate": present & required == required}


def _combine(ancestors: list[dict], target: dict) -> bool:
    return all(check["predicate"] for check in ancestors) and target["predicate"]


def evaluate(request: object) -> dict:
    """Evaluate the exact invented-record contract, never OS authorization.

    All fields validate before a model denial/unsupported result. Report ancestor
    search and target bit predicates independently; model_permits has meaning only
    under the supplied ordinary-DAC assumptions. No caller object is mutated.
    """
    try:
        subject, ancestors, target, operation, unsupported = _validated(request)
        if unsupported:
            return {**_outcome("unsupported", "outside_subset"), "unsupported_reasons": unsupported}
        ancestor_checks = [_check(subject, node, 1) for node in ancestors]
        target_check = _check(subject, target, OPERATIONS[operation][1])
        return {**_outcome("model_complete", "ordinary_predicates_only"),
                "model_permits": _combine(ancestor_checks, target_check),
                "ancestor_checks": ancestor_checks, "target_check": target_check}
    except _Invalid as error:
        return _outcome(error.status, error.reason)


def _depth(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise _Invalid("depth_limit", "over_limit")
        elif char in "]}":
            depth -= 1


def _unique(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Invalid("duplicate_key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > MAX_NUMERIC_CHARS:
        raise _Invalid("numeric_token_limit", "over_limit")
    return int(token)


def _reject_number(token: str) -> None:
    if len(token) > MAX_NUMERIC_CHARS:
        raise _Invalid("numeric_token_limit", "over_limit")
    raise _Invalid("non_integer_number")


def analyze_json(raw: object) -> dict:
    """Strict bounded exact UTF-8 JSON bytes; no file or process context lookup."""
    if type(raw) is not bytes:
        return _outcome("rejected", "input_type")
    if len(raw) > MAX_INPUT_BYTES:
        return _outcome("over_limit", "input_limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        _depth(text)
        request = json.loads(text, object_pairs_hook=_unique, parse_int=_integer,
                             parse_float=_reject_number, parse_constant=_reject_number)
        return evaluate(request)
    except _Invalid as error:
        return _outcome(error.status, error.reason)
    except (UnicodeError, ValueError, RecursionError):
        return _outcome("rejected", "invalid_json_or_utf8")


def serialize_report(report: dict) -> bytes:
    """Escape/cap internally constructed reports including one final newline."""
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False,
                         separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_OUTPUT_BYTES:
        return serialize_report(_outcome("over_limit", "output_limit"))
    return encoded
