# tests/export_batch_sim.py

import sys
from pathlib import Path


def simulate_export(ledger: Path) -> int:
    # Pretend anything with "invalid" in its name fails, others succeed.
    name = ledger.name

    if "invalid" in name:
        print(f"EXPORT FAILED: Ledger is INVALID: {ledger}")
        return 1

    bundle = ledger.with_suffix(".gcbundle")
    print("GuardClaw GEF Evidence Bundle Export")
    print(f"Bundle created: {bundle}")
    print("Bundle contents:")
    print("  ledger.gef")
    print("  manifest.json")
    print("  verification.json")
    print("  publickey.json")
    print("  report.html")
    print("Share this bundle for independent verification")
    print()
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: export_batch_sim.py LEDGER...", file=sys.stderr)
        return 2

    exit_code = 0
    for arg in argv[1:]:
        ledger = Path(arg)
        code = simulate_export(ledger)
        if code != 0:
            exit_code = code  # keep non-zero if any failed

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))