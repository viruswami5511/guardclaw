from pathlib import Path
import subprocess
import sys


def test_export_batch_mixed_valid_and_invalid(tmp_path: Path) -> None:
    # Arrange: 3 dummy ledger paths
    valid1 = tmp_path / "ledger_valid_1.gef"
    valid2 = tmp_path / "ledger_valid_2.gef"
    invalid = tmp_path / "ledger_invalid_1.gef"

    # Files don't need real content for UX simulation
    for p in [valid1, valid2, invalid]:
        p.write_text("dummy", encoding="utf-8")

    # Act: run our batch simulator
    script = Path("tests/export_batch_sim.py")
    result = subprocess.run(
        [sys.executable, str(script), str(valid1), str(invalid), str(valid2)],
        capture_output=True,
        text=True,
        check=False,
    )

    # Assert: exit code is non-zero because at least one failed
    assert result.returncode != 0

    stdout = result.stdout

    # Two successful exports: they should each show the success block
    assert stdout.count("GuardClaw GEF Evidence Bundle Export") == 2
    assert stdout.count("Bundle created:") == 2
    assert stdout.count("Bundle contents:") == 2
    assert stdout.count("Share this bundle for independent verification") == 2

    # Failure visible for the invalid ledger
    assert "EXPORT FAILED" in stdout
    assert "ledger_invalid_1.gef" in stdout

    # Optional: print transcript during pytest -s so you can *see* it
    print("--- batch stdout ---")
    print(stdout)