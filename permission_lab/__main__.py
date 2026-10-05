"""Bounded JSON reports for pure invented records; no live Linux operations."""

import argparse
import json
import sys

from .core import MAX_INPUT_BYTES, analyze_json, evaluate, serialize_report
from .fixtures import cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Ordinary mode predicates; actual access unverified")
    parser.add_argument("command", choices=("analyze", "demo"))
    args = parser.parse_args()
    try:
        if args.command == "analyze":
            report = analyze_json(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        else:
            results = []
            for name, request, expected in cases():
                decision = evaluate(request)
                target = decision.get("target_check", {})
                actual = (target.get("selected_class"), target.get("present_bits"), target.get("required_bits"),
                          target.get("predicate"), decision.get("model_permits"))
                results.append({"case": name, "report": decision, "expected": expected, "passed": actual == expected})
            report = {"mode": "invented_record_predicates", "actual_access": "unverified",
                      "cases": results, "passed": all(case["passed"] for case in results)}
        payload = serialize_report(report)
        emitted = json.loads(payload)
        if sys.stdout.buffer.write(payload) != len(payload):
            raise OSError("short output write")
        sys.stdout.buffer.flush()
    except OSError:
        sys.stdout = None
        try:
            print('{"error":"input_or_output_failure"}', file=sys.stderr)
        except OSError:
            pass
        return 3
    if emitted.get("status") == "over_limit":
        return 2
    if args.command == "demo":
        return 0 if report["passed"] else 1
    if not report["complete"]:
        return 2
    return 0 if report["model_permits"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
