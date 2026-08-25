#!/usr/bin/env python3
"""Multi-round data collection runner for Aliyun/Linux experiments.

The default mode runs examples/perf_test for at least 10 outer rounds.  The
Rust example already averages its hot paths internally; this wrapper captures
cross-round variance, raw logs, CSV rows, and JSON summaries.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]


PERF_PATTERNS: list[tuple[str, str, type]] = [
    ("setup_ms", r"Setup \(\d+ bit\):\s+([0-9.]+) ms", float),
    ("keygen_5_attrs_ms", r"KeyGen \(5 attributes\):\s+([0-9.]+) ms", float),
    (
        "pabs_sign_ms",
        r"Sign \(Policy = admin AND finance\):\s+([0-9.]+) ms",
        float,
    ),
    ("pabs_verify_ms", r"Verify:\s+([0-9.]+) ms \(Result:\s*(true|false)\)", float),
    ("signature_raw_hashmap_bytes", r"Signature size \(raw HashMap\):\s+(\d+) bytes", int),
    ("signature_struct_bytes", r"Signature size \(sig_struct\):\s+(\d+) bytes", int),
    (
        "signature_compressed_bytes",
        r"Signature size \(CompressedSignature\):\s+(\d+) bytes",
        int,
    ),
    ("compression_ratio", r"Compression Ratio:\s+([0-9.]+)x", float),
    ("mlwe_core_sign_ms", r"MLWE core Sign:\s+([0-9.]+) ms", float),
    (
        "mlwe_core_verify_ms",
        r"MLWE core Verify:\s+([0-9.]+) ms \(Result:\s*(true|false)\)",
        float,
    ),
    ("mlwe_core_signature_bytes", r"MLWE core Signature size:\s+(\d+) bytes", int),
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def local_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def run_command(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_sec": time.perf_counter() - started,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def command_text(cmd: list[str], cwd: Path) -> str | None:
    try:
        res = run_command(cmd, cwd)
    except (OSError, subprocess.SubprocessError):
        return None
    if res["returncode"] != 0:
        return None
    return str(res["stdout"]).strip()


def read_first_cpu_model() -> str | None:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists():
        return None
    for line in cpuinfo.read_text(errors="replace").splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
        if line.lower().startswith("hardware"):
            return line.split(":", 1)[1].strip()
    return None


def read_cpu_flags() -> list[str]:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists():
        return []
    for line in cpuinfo.read_text(errors="replace").splitlines():
        lowered = line.lower()
        if lowered.startswith("flags") or lowered.startswith("features"):
            _, flags = line.split(":", 1)
            return sorted(set(flags.strip().split()))
    return []


def read_ram_gb() -> float | None:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return None
    for line in meminfo.read_text(errors="replace").splitlines():
        if line.startswith("MemTotal:"):
            kb = float(line.split()[1])
            return round(kb / 1024 / 1024, 2)
    return None


def collect_environment(project_dir: Path) -> dict[str, Any]:
    return {
        "timestamp_utc": utc_now(),
        "project_dir": str(project_dir),
        "python_version": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "uname": " ".join(platform.uname()),
        "cpu_model": read_first_cpu_model() or platform.processor() or "unknown",
        "cpu_flags": read_cpu_flags(),
        "ram_gb": read_ram_gb(),
        "rustc": command_text(["rustc", "--version"], project_dir),
        "cargo": command_text(["cargo", "--version"], project_dir),
        "git_commit": command_text(["git", "rev-parse", "--short", "HEAD"], project_dir),
        "cargo_home": os.environ.get("CARGO_HOME"),
        "rustup_dist_server": os.environ.get("RUSTUP_DIST_SERVER"),
        "rustup_update_root": os.environ.get("RUSTUP_UPDATE_ROOT"),
        "rustflags": os.environ.get("RUSTFLAGS"),
    }


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def append_jsonl(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def parse_perf_output(stdout: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, pattern, caster in PERF_PATTERNS:
        match = re.search(pattern, stdout)
        if not match:
            continue
        parsed[key] = caster(match.group(1))
        if key == "pabs_verify_ms" and len(match.groups()) >= 2:
            parsed["pabs_verify_result"] = match.group(2).lower() == "true"
        if key == "mlwe_core_verify_ms" and len(match.groups()) >= 2:
            parsed["mlwe_core_verify_result"] = match.group(2).lower() == "true"
    return parsed


def try_parse_json_from_stdout(stdout: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    for idx, char in enumerate(stdout):
        if char != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(stdout[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("results" in obj or "platform" in obj):
            return obj
    return None


def flatten_criterion_doc(round_no: int, bench_target: str, doc: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for bench_name, result in doc.get("results", {}).items():
        rows.append(
            {
                "round": round_no,
                "bench_target": bench_target,
                "benchmark": bench_name,
                "mean_us": result.get("mean_us"),
                "ci_low_us": result.get("ci_low_us"),
                "ci_high_us": result.get("ci_high_us"),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def numeric_values(rows: list[dict[str, Any]], key: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(key)
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, (int, float)) and math.isfinite(float(value)):
            values.append(float(value))
    return values


def describe(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "mean": statistics.fmean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def summarize_perf(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metric_names = sorted(
        {
            key
            for row in rows
            for key, value in row.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        }
        - {"round", "exit_code"}
    )
    return {name: describe(numeric_values(rows, name)) for name in metric_names}


def summarize_criterion(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("bench_target")), str(row.get("benchmark")))
        grouped.setdefault(key, []).append(row)
    summary: list[dict[str, Any]] = []
    for (bench_target, benchmark), group_rows in sorted(grouped.items()):
        summary.append(
            {
                "bench_target": bench_target,
                "benchmark": benchmark,
                "mean_us": describe(numeric_values(group_rows, "mean_us")),
                "ci_low_us": describe(numeric_values(group_rows, "ci_low_us")),
                "ci_high_us": describe(numeric_values(group_rows, "ci_high_us")),
            }
        )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run at least 10 rounds of PABS-CRF data collection on Aliyun/Linux."
    )
    parser.add_argument("--rounds", type=int, default=10, help="Outer rounds, minimum 10 by default.")
    parser.add_argument(
        "--allow-less-for-smoke-test",
        action="store_true",
        help="Allow fewer than 10 rounds only for local smoke tests.",
    )
    parser.add_argument(
        "--mode",
        choices=["perf", "criterion", "all"],
        default="perf",
        help="perf runs examples/perf_test; criterion runs Criterion; all runs both.",
    )
    parser.add_argument(
        "--criterion-bench",
        action="append",
        default=[],
        help="Criterion bench target. Repeat for multiple targets. Default in criterion/all: sign.",
    )
    parser.add_argument("--criterion-sample-size", type=int, default=10)
    parser.add_argument("--features", default="", help="Cargo feature string, for example: avx512.")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--timeout-sec", type=int, default=None)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.rounds < 10 and not args.allow_less_for_smoke_test:
        parser.error("--rounds must be at least 10. Use --allow-less-for-smoke-test only for local smoke tests.")

    project_dir = PROJECT_DIR
    out_dir = args.out_dir or project_dir / "test-results" / "aliyun" / local_stamp()
    logs_dir = out_dir / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    environment = collect_environment(project_dir)
    write_json(out_dir / "environment.json", environment)
    run_config = vars(args).copy()
    if run_config.get("out_dir") is not None:
        run_config["out_dir"] = str(run_config["out_dir"])
    run_config["project_dir"] = str(project_dir)
    write_json(out_dir / "run_config.json", run_config)

    perf_rows: list[dict[str, Any]] = []
    criterion_rows: list[dict[str, Any]] = []
    criterion_failures: list[dict[str, Any]] = []

    env = os.environ.copy()
    if args.features:
        env["CARGO_FEATURES_FOR_COLLECTION"] = args.features

    if not args.skip_build:
        build_cmd = ["cargo", "build", "--release"]
        if args.features:
            build_cmd += ["--features", args.features]
        build_cmd += ["--example", "perf_test"]
        build_res = run_command(build_cmd, project_dir, env=env, timeout=args.timeout_sec)
        write_text(logs_dir / "00_build.stdout.log", build_res["stdout"])
        write_text(logs_dir / "00_build.stderr.log", build_res["stderr"])
        if build_res["returncode"] != 0:
            write_json(out_dir / "summary.json", {"status": "build_failed", "build": build_res})
            print(f"Build failed. See {logs_dir / '00_build.stderr.log'}", file=sys.stderr)
            return int(build_res["returncode"])

    criterion_benches = args.criterion_bench or ["sign"]
    bash_path = shutil.which("bash")

    for round_no in range(1, args.rounds + 1):
        print(f"[round {round_no}/{args.rounds}] starting", flush=True)

        if args.mode in {"perf", "all"}:
            perf_cmd = ["cargo", "run", "--release"]
            if args.features:
                perf_cmd += ["--features", args.features]
            perf_cmd += ["--example", "perf_test"]
            res = run_command(perf_cmd, project_dir, env=env, timeout=args.timeout_sec)
            write_text(logs_dir / f"round_{round_no:02d}_perf.stdout.log", res["stdout"])
            write_text(logs_dir / f"round_{round_no:02d}_perf.stderr.log", res["stderr"])
            row = {
                "round": round_no,
                "exit_code": res["returncode"],
                "command_duration_sec": res["duration_sec"],
            }
            row.update(parse_perf_output(res["stdout"]))
            perf_rows.append(row)
            append_jsonl(out_dir / "perf_rounds.jsonl", row)
            if res["returncode"] != 0:
                print(f"[round {round_no}] perf_test failed", file=sys.stderr)

        if args.mode in {"criterion", "all"}:
            if bash_path is None:
                print("bash is required for scripts/cross_platform_bench.sh", file=sys.stderr)
                return 127
            for bench_target in criterion_benches:
                bench_cmd = [
                    bash_path,
                    "scripts/cross_platform_bench.sh",
                    "--sample-size",
                    str(args.criterion_sample_size),
                    "--bench",
                    bench_target,
                ]
                if args.features:
                    bench_cmd += ["--features", args.features]
                res = run_command(bench_cmd, project_dir, env=env, timeout=args.timeout_sec)
                stem = f"round_{round_no:02d}_criterion_{bench_target}"
                write_text(logs_dir / f"{stem}.stdout.log", res["stdout"])
                write_text(logs_dir / f"{stem}.stderr.log", res["stderr"])
                doc = try_parse_json_from_stdout(res["stdout"])
                if res["returncode"] == 0 and doc is not None:
                    append_jsonl(
                        out_dir / "criterion_round_docs.jsonl",
                        {"round": round_no, "bench_target": bench_target, "doc": doc},
                    )
                    rows = flatten_criterion_doc(round_no, bench_target, doc)
                    criterion_rows.extend(rows)
                    for row in rows:
                        append_jsonl(out_dir / "criterion_rounds.jsonl", row)
                else:
                    append_jsonl(
                        out_dir / "criterion_errors.jsonl",
                        {
                            "round": round_no,
                            "bench_target": bench_target,
                            "exit_code": res["returncode"],
                            "duration_sec": res["duration_sec"],
                        },
                    )
                    criterion_failures.append(
                        {
                            "round": round_no,
                            "bench_target": bench_target,
                            "exit_code": res["returncode"],
                        }
                    )
                    print(f"[round {round_no}] criterion {bench_target} failed or produced no JSON", file=sys.stderr)

    write_csv(out_dir / "perf_rounds.csv", perf_rows)
    write_csv(out_dir / "criterion_rounds.csv", criterion_rows)

    failed_perf_rounds = [row["round"] for row in perf_rows if row.get("exit_code") != 0]
    status = "ok" if not failed_perf_rounds and not criterion_failures else "completed_with_failures"

    summary = {
        "status": status,
        "generated_at_utc": utc_now(),
        "rounds": args.rounds,
        "mode": args.mode,
        "out_dir": str(out_dir),
        "perf": {
            "rows": len(perf_rows),
            "failed_rounds": failed_perf_rounds,
            "metrics": summarize_perf(perf_rows),
        },
        "criterion": {
            "rows": len(criterion_rows),
            "bench_targets": criterion_benches if args.mode in {"criterion", "all"} else [],
            "failed_runs": criterion_failures,
            "metrics": summarize_criterion(criterion_rows),
        },
    }
    write_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "perf_summary.csv",
        [{"metric": key, **value} for key, value in summary["perf"]["metrics"].items()],
    )
    write_csv(
        out_dir / "criterion_summary.csv",
        [
            {
                "bench_target": item["bench_target"],
                "benchmark": item["benchmark"],
                "mean_us_count": item["mean_us"].get("count"),
                "mean_us_mean": item["mean_us"].get("mean"),
                "mean_us_stdev": item["mean_us"].get("stdev"),
                "mean_us_min": item["mean_us"].get("min"),
                "mean_us_max": item["mean_us"].get("max"),
            }
            for item in summary["criterion"]["metrics"]
        ],
    )

    print(f"Results written to: {out_dir}")
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
