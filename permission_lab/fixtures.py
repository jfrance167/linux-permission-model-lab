"""Invented records and hand-fixed expected bits, never host metadata."""


def request(mode="0400", operation="file_read", *, uid=101, gid=20, groups=(),
            owner=101, owning_group=10, ancestor_mode="0100", kind="regular") -> dict:
    return {"version": 1, "profile": "ordinary_dac_v1", "unsupported_features": [],
            "subject": {"fsuid": uid, "fsgid": gid, "supplementary_gids": list(groups)},
            "ancestors": [{"id": "Parent", "kind": "directory", "owner_uid": 101,
                           "group_gid": 10, "mode": ancestor_mode}],
            "target": {"id": "Target", "kind": kind, "owner_uid": owner,
                       "group_gid": owning_group, "mode": mode}, "operation": operation}


def cases() -> list[tuple[str, dict, tuple]]:
    # expected=(target class, present, required, target predicate, overall).
    # Make ancestor searchable for nonowner examples with 0111.
    return [
        ("Owner has no fallback", request("0044"), ("owner", 0, 4, False, False)),
        ("Group has no other fallback", request("0004", uid=202, gid=10, ancestor_mode="0111"),
         ("group", 0, 4, False, False)),
        ("Supplementary group", request("0040", uid=202, groups=(10,), ancestor_mode="0111"),
         ("group", 4, 4, True, True)),
        ("Other class", request("0004", uid=202, ancestor_mode="0111"), ("other", 4, 4, True, True)),
        ("All requested bits", request("0400", "file_read_write"), ("owner", 4, 6, False, False)),
        ("Ancestor search independently fails", request("0400", ancestor_mode="0600"),
         ("owner", 4, 4, True, False)),
        ("Directory names predicate", request("0400", "directory_list_names", kind="directory"),
         ("owner", 4, 4, True, True)),
        ("Directory search without names read", request("0100", "directory_list_names", kind="directory"),
         ("owner", 1, 4, False, False)),
        ("Directory search predicate", request("0100", "directory_search", kind="directory"),
         ("owner", 1, 1, True, True)),
        ("File write without parent write", request("0200", "file_write"), ("owner", 2, 2, True, True)),
        ("Group zero has no bypass", request("0000", uid=202, gid=0, owning_group=0, ancestor_mode="0111"),
         ("group", 0, 4, False, False)),
    ]
