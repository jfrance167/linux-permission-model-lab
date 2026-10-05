"""Catch two in-memory faults, restore originals, and rerun fixed regressions.

Usage: python tools/check_mutations.py
Trusted fixtures only; no source edits/network/external commands. Exit zero
requires both defects caught and restored regressions passed. Not a coverage score.
"""

from io import StringIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from permission_lab import core
from test_core import CoreTests


def run_case(name: str) -> bool:
    result = unittest.TextTestRunner(stream=StringIO()).run(unittest.TestSuite([CoreTests(name)]))
    return result.wasSuccessful()


def main() -> int:
    selected = core._selected

    def wrong_union(subject, node):
        label, bits = selected(subject, node)
        mode = node[4]
        return label, bits | ((mode >> 6) & 7) | ((mode >> 3) & 7) | (mode & 7)

    mutations = []
    with patch.object(core, "_selected", wrong_union):
        mutations.append({"mutation": "union_of_all_classes",
                          "detected": not run_case("test_fixed_oracles")})
    with patch.object(core, "_combine", lambda ancestors, target: target["predicate"]):
        mutations.append({"mutation": "ignoring_ancestor_search",
                          "detected": not run_case("test_ancestor_checks_independent")})
    restored = all(run_case(name) for name in ("test_fixed_oracles", "test_ancestor_checks_independent"))
    print(json.dumps({"mutations": mutations, "restored_tests_pass": restored,
                      "scope": "two in-memory faults; no source mutation"}, indent=2))
    return 0 if restored and all(item["detected"] for item in mutations) else 1


if __name__ == "__main__":
    raise SystemExit(main())
