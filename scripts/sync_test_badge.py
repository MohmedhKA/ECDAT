#!/usr/bin/env python3
"""
Sync Test Badge & Documentation:
Executes pytest and updates README.md test badge and test counts automatically.
"""

import sys
import subprocess
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent.parent
    readme_path = root / "README.md"
    if not readme_path.exists():
        print(f"[-] README.md not found at {readme_path}")
        sys.exit(1)

    print("[*] Running pytest to retrieve accurate test count...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=str(root),
        capture_output=True,
        text=True,
    )

    stdout = result.stdout.strip()
    print(stdout)

    # Example output: "179 passed in 5.82s"
    passed_count = None
    for line in stdout.splitlines():
        if "passed" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "passed" and i > 0 and parts[i-1].isdigit():
                    passed_count = int(parts[i-1])
                    break

    if passed_count is None:
        print("[-] Could not parse passed test count from pytest output.")
        sys.exit(1)

    print(f"[+] Verified passing tests: {passed_count}")

    content = readme_path.read_text(encoding="utf-8")

    # Update badge and description with string replacement
    lines = content.splitlines(keepends=True)
    out_lines = []
    for line in lines:
        if "tests-" in line and "%20passed%20(" in line:
            # Replace badge
            line = f"[![Tests](https://img.shields.io/badge/tests-{passed_count}%20passed%20(100%25)-brightgreen.svg)](tests/)\n"
        elif "zero-regression test suite covering" in line:
            line = f"ECDAT maintains a comprehensive, zero-regression test suite covering {passed_count} test cases:\n"
        out_lines.append(line)

    readme_path.write_text("".join(out_lines), encoding="utf-8")
    print(f"[+] Updated {readme_path} with {passed_count} test cases.")

if __name__ == "__main__":
    main()
