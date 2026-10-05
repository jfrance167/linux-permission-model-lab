"""Fixed independent ordinary-mode expectations and fail-closed boundary tests."""

from copy import deepcopy
import builtins
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from permission_lab import core
from permission_lab.fixtures import cases, request


class CoreTests(unittest.TestCase):
    def incomplete(self, value, status="rejected"):
        report = core.evaluate(value)
        self.assertEqual(report["status"], status)
        self.assertFalse(report["complete"])
        self.assertEqual(report["actual_access"], "unverified")
        self.assertNotIn("model_permits", report)
        self.assertNotIn("target_check", report)
        return report

    def test_fixed_oracles(self):
        for name, value, expected in cases():
            with self.subTest(name=name):
                report = core.evaluate(value)
                check = report["target_check"]
                self.assertEqual((check["selected_class"], check["present_bits"],
                                  check["required_bits"], check["predicate"],
                                  report["model_permits"]), expected)
                self.assertEqual(report["status"], "model_complete")
                self.assertEqual(report["actual_access"], "unverified")

    def test_ancestor_checks_independent(self):
        value = request(ancestor_mode="0600")
        later = deepcopy(value["ancestors"][0])
        later.update(id="Later", owner_uid=202, group_gid=20, mode="0010")
        value["ancestors"].append(later)
        report = core.evaluate(value)
        self.assertEqual(report["ancestor_checks"], [
            {"id": "Parent", "selected_class": "owner", "present_bits": 6,
             "required_bits": 1, "predicate": False},
            {"id": "Later", "selected_class": "group", "present_bits": 1,
             "required_bits": 1, "predicate": True}])
        self.assertTrue(report["target_check"]["predicate"])
        self.assertFalse(report["model_permits"])

    def test_owner_precedes_group_and_all_required_bits(self):
        # Owner cannot borrow group/other bits even when also in owning group.
        value = request(mode="0047", gid=10)
        self.assertFalse(core.evaluate(value)["model_permits"])
        for mode, expected in (("0200", False), ("0400", False), ("0600", True)):
            self.assertEqual(core.evaluate(request(mode=mode, operation="file_read_write"))
                             ["model_permits"], expected)

    def test_fsgid_zero_is_ordinary_group(self):
        for mode, expected in (("0000", False), ("0040", True)):
            report = core.evaluate(request(uid=202, gid=0, owning_group=0,
                                           mode=mode, ancestor_mode="0111"))
            self.assertEqual(report["target_check"]["selected_class"], "group")
            self.assertEqual(report["model_permits"], expected)

    def test_execute_bit_is_only_a_predicate(self):
        for mode, expected in (("0400", False), ("0100", True)):
            report = core.evaluate(request(mode=mode, operation="file_execute_bit"))
            self.assertEqual(report["target_check"]["required_bits"], 1)
            self.assertEqual(report["model_permits"], expected)
            self.assertIn("syscall_success", report["not_verified"])

    def test_zero_mode_and_special_ancestor(self):
        self.assertFalse(core.evaluate(request(mode="0000"))["model_permits"])
        self.incomplete(request(ancestor_mode="1755"), "unsupported")
        fixture = request(); fixture["version"] = True; self.incomplete(fixture)
        fixture["version"] = -1; self.incomplete(fixture)

    def test_unsupported_context(self):
        for field, value in (("version", 2), ("profile", "Other"),
                             ("unsupported_features", ["acl"]), ("operation", "delete")):
            fixture = request()
            fixture[field] = value
            self.incomplete(fixture, "unsupported")
        fixture = request(uid=0, mode="4755")
        fixture["unsupported_features"] = ["capabilities", "acl"]
        self.assertEqual(self.incomplete(fixture, "unsupported")["unsupported_reasons"],
                         ["acl", "capabilities", "root", "special_mode"])
        for operation in ("create", "delete", "rename"):
            self.incomplete(request(operation=operation), "unsupported")
        for feature in core.FEATURES:
            fixture = request()
            fixture["unsupported_features"] = [feature]
            self.incomplete(fixture, "unsupported")

    def test_later_invalid_not_masked(self):
        roots = [request(uid=0), request(mode="4755"), request(ancestor_mode="0000"), request()]
        roots[3]["unsupported_features"] = ["acl"]
        version = request(); version["version"] = 2; roots.append(version)
        profile = request(); profile["profile"] = "Other"; roots.append(profile)
        operation = request(operation="delete"); roots.append(operation)
        for value in roots:
            with self.subTest(value=value):
                later = deepcopy(value["ancestors"][0])
                later.update(id="Later", mode="8888")
                value["ancestors"].append(later)
                self.incomplete(value)
                value["ancestors"].pop()
                value["target"]["owner_uid"] = True
                self.incomplete(value)

    def test_duplicate_groups_nodes_features(self):
        self.incomplete(request(groups=(10, 10)))
        for location in ("ancestor", "target"):
            fixture = request()
            if location == "ancestor":
                fixture["ancestors"].append(deepcopy(fixture["ancestors"][0]))
            else:
                fixture["target"]["id"] = "Parent"
            self.incomplete(fixture)
        fixture = request(); fixture["unsupported_features"] = ["acl", "acl"]
        self.incomplete(fixture)

    def test_exact_types_without_coercion(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("coercion")
            def __int__(self):
                raise AssertionError("coercion")
        class DictSubclass(dict):
            def __iter__(self):
                raise AssertionError("custom iteration")
        class ListSubclass(list):
            def __iter__(self):
                raise AssertionError("custom iteration")
        class StrSubclass(str):
            pass
        self.incomplete(DictSubclass(request()))
        for value in (True, 1.0, "101", Hostile(), None, -1, 1_000_000_000):
            fixture = request(); fixture["subject"]["fsuid"] = value
            self.incomplete(fixture)
        for value in (ListSubclass([10]), (10,), None):
            fixture = request(); fixture["subject"]["supplementary_gids"] = value
            self.incomplete(fixture)
        for value in (Hostile(), StrSubclass("0400"), 0o400, "400", "0o400", "0400\n"):
            fixture = request(); fixture["target"]["mode"] = value
            self.incomplete(fixture)
        # Built-in dictionary with non-string key: no post-insertion hashing/equality.
        class Key:
            def __hash__(self):
                return 1
            def __eq__(self, other):
                raise AssertionError("key equality")
        fixture = request(); fixture.pop("version"); fixture[Key()] = 1
        self.incomplete(fixture)

    def test_shapes_identifiers_and_kind(self):
        for field in request():
            fixture = request(); fixture.pop(field); self.incomplete(fixture)
        fixture = request(); fixture["extra"] = 1; self.incomplete(fixture)
        for text in ("", "../x", "A/B", "A\\B", "A\x00", "A\n", "é", "A" * 33, "\ud800"):
            fixture = request(); fixture["target"]["id"] = text; self.incomplete(fixture)
        self.incomplete(request(kind="symlink"))
        self.incomplete(request(kind="directory"))
        self.incomplete(request(operation="directory_search"))
        self.incomplete(request(operation="execute"))
        fixture = request(); fixture["ancestors"][0]["kind"] = "regular"; self.incomplete(fixture)
        fixture = request(); fixture["unsupported_features"] = ["unknown"]; self.incomplete(fixture)

    def test_api_bounds_and_boundary_acceptance(self):
        self.incomplete(request(groups=range(17)), "over_limit")
        fixture = request(); fixture["ancestors"] = [] ; self.incomplete(fixture)
        fixture = request()
        fixture["ancestors"] = [dict(fixture["ancestors"][0], id=f"N{i}") for i in range(9)]
        self.incomplete(fixture, "over_limit")
        fixture["ancestors"].pop()
        self.assertTrue(core.evaluate(fixture)["complete"])
        fixture = request(groups=range(16)); fixture["target"]["id"] = "A" * 32
        fixture["subject"]["fsuid"] = 999_999_999
        self.assertTrue(core.evaluate(fixture)["complete"])
        fixture["unsupported_features"] = ["acl"] * 17
        self.incomplete(fixture, "over_limit")

    def test_json_boundaries(self):
        raw = json.dumps(request()).encode()
        self.assertTrue(core.analyze_json(raw)["complete"])
        self.assertTrue(core.analyze_json(raw + b" " * (core.MAX_INPUT_BYTES-len(raw)))["complete"])
        for value, status in ((bytearray(raw), "rejected"), (b"\xff", "rejected"),
                              (raw+b" " * core.MAX_INPUT_BYTES, "over_limit"),
                              (b"[" * 7 + b"]" * 7, "over_limit"),
                              (b'{"x":12345678901}', "over_limit"),
                              (b'{"x":1.0}', "rejected"), (b'{"x":NaN}', "rejected"),
                              (b'{"version":1,"version":1}', "rejected"),
                              (raw+b"{}", "rejected"), (b"{", "rejected")):
            report = core.analyze_json(value)
            self.assertEqual(report["status"], status)
            self.assertNotIn("model_permits", report)
        fixture = request(); fixture["target"]["id"] = '[{"x"}]'
        self.assertEqual(core.analyze_json(json.dumps(fixture).encode())["status"], "rejected")

    def test_no_mutation_and_json_equivalence(self):
        for _, fixture, _ in cases():
            before = deepcopy(fixture)
            direct = core.evaluate(fixture)
            self.assertEqual(fixture, before)
            self.assertEqual(core.analyze_json(json.dumps(fixture).encode()), direct)

    def test_output_bound_and_escaped_data(self):
        output = core.serialize_report({"text": "\n\x1b\ud800"})
        self.assertEqual(output.count(b"\n"), 1)
        self.assertNotIn(b"\x1b", output)
        self.assertEqual(json.loads(output)["text"], "\n\x1b\ud800")
        report = json.loads(core.serialize_report({"text": "x" * core.MAX_OUTPUT_BYTES}))
        self.assertEqual(report["status"], "over_limit")
        self.assertFalse(report["complete"])

    def test_no_host_capabilities(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("host capability called")
        # Imports and mock setup happen before entering the guard. The trusted
        # harness may inspect its own files outside this model invocation.
        guards = [(builtins, name) for name in ("open", "eval", "exec")]
        guards += [(os, name) for name in ("access", "stat", "lstat", "chmod", "chown", "umask", "walk")
                   if hasattr(os, name)]
        guards += [(os, name) for name in ("getuid", "geteuid", "getgid", "getegid", "getgroups")
                   if hasattr(os, name)]
        guards += [(Path, "resolve"), (socket, "socket"), (socket, "create_connection"),
                   (subprocess, "Popen")]
        fixture = request()
        raw = json.dumps(fixture).encode()
        contexts = [patch.object(obj, name, forbidden) for obj, name in guards]
        with ExitStack() as stack:
            for context in contexts:
                stack.enter_context(context)
            self.assertTrue(core.evaluate(fixture)["model_permits"])
            self.assertTrue(core.analyze_json(raw)["model_permits"])
            self.assertEqual(core.evaluate({})["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
