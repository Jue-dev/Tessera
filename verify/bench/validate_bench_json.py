import json
import subprocess
import sys


def validate(executable: str) -> None:
    completed = subprocess.run(
        [executable, "--json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload = json.loads(completed.stdout)
    records = payload.get("benchmarks") if isinstance(payload, dict) and "benchmarks" in payload else [payload]
    if not records:
        raise ValueError(f"{executable}: no benchmark records")
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"{executable}: record is not an object")
        if not isinstance(record.get("name"), str) or not record["name"]:
            raise ValueError(f"{executable}: missing benchmark name")
        if not isinstance(record.get("iterations"), int) or record["iterations"] <= 0:
            raise ValueError(f"{executable}: invalid iterations")
        if not isinstance(record.get("ns_per_op"), (int, float)) or record["ns_per_op"] <= 0:
            raise ValueError(f"{executable}: invalid ns_per_op")
        if not isinstance(record.get("mb_per_s"), (int, float)) or record["mb_per_s"] < 0:
            raise ValueError(f"{executable}: invalid mb_per_s")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: validate_bench_json.py EXECUTABLE...", file=sys.stderr)
        return 2
    for executable in sys.argv[1:]:
        validate(executable)
        print(f"valid JSON benchmark output: {executable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
