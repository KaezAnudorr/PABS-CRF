#!/usr/bin/env python3
"""
Comprehensive PABS-CRF Benchmark Runner with Full Optimization Testing

This script runs benchmarks with:
- All security levels (L1/L3/L5)
- All attribute counts (1, 3, 5, 10, 20)
- All policy types (simple AND/OR, complex nested)
- With/without AVX-512 optimization
- NTT cache statistics
- Puncture operations
- Full data collection and analysis
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

# Extended pattern matching for comprehensive test
COMPREHENSIVE_PATTERNS: list[tuple[str, str, type]] = [
    # Security level and test config
    ("security_level", r"Security Level:\s+(\d+)\s+bits", int),
    ("optimization_level", r"Optimization Level:\s+(\w+)", str),
    ("avx512_enabled", r"AVX-512:\s+(ENABLED|DISABLED)", lambda x: x == "ENABLED"),

    # Cache statistics
    ("ntt_cache_capacity", r"NTT Cache: capacity=(\d+)", int),
    ("ntt_cache_len", r"NTT Cache:.*len=(\d+)", int),
    ("ntt_cache_hits", r"NTT Cache:.*hits=(\d+)", int),
    ("ntt_cache_misses", r"NTT Cache:.*misses=(\d+)", int),
    ("matrix_cache_hits", r"Matrix Cache:.*hits=(\d+)", int),
    ("matrix_cache_misses", r"Matrix Cache:.*misses=(\d+)", int),

    # Setup time
    ("setup_ms", r"^Setup:\s+([0-9.]+)\s+ms", float),

    # KeyGen with attribute counts
    ("keygen_ms", r"KeyGen:\s+([0-9.]+)\s+ms", float),
    ("keygen_attr_count", r"Testing with\s+(\d+)\s+Attributes", int),

    # Sign/Verify times with policy types
    ("sign_ms", r"Sign:\s+([0-9.]+)\s+ms", float),
    ("sign_errors", r"Sign:.*errors:\s+(\d+)", int),
    ("verify_ms", r"Verify:\s+([0-9.]+)\s+ms", float),
    ("verify_result", r"Verify:.*result:\s+(true|false)", lambda x: x == "true"),
    ("verify_errors", r"Verify:.*errors:\s+(\d+)", int),

    # Signature sizes
    ("signature_raw_bytes", r"raw=(\d+)\s+bytes", int),
    ("signature_struct_bytes", r"struct=(\d+)\s+bytes", int),
    ("signature_compressed_bytes", r"compressed=(\d+)\s+bytes", int),
    ("compression_ratio", r"Compression Ratio:\s+([0-9.]+)x", float),

    # Puncture operations
    ("puncture_avg_ms", r"Puncture:\s+([0-9.]+)\s+ms\s+\(avg\)", float),
    ("puncture_min_ms", r"Puncture:.*\(min\),\s+([0-9.]+)\s+ms", float),
    ("puncture_max_ms", r"Puncture:.*\(max\),\s+([0-9.]+)\s+ms", float),
    ("puncture_successful_count", r"Puncture:.*,\s+(\d+)\s+successful", int),

    # MLWE baseline
    ("mlwe_sign_ms", r"MLWE Sign:\s+([0-9.]+)\s+ms", float),
    ("mlwe_verify_ms", r"MLWE Verify:\s+([0-9.]+)\s+ms", float),
    ("mlwe_verify_result", r"MLWE Verify:.*result:\s+(true|false)", lambda x: x == "true"),
    ("mlwe_signature_bytes", r"MLWE Signature Size:\s+(\d+)\s+bytes", int),

    # Final cache hit rates
    ("ntt_hit_rate", r"NTT Cache:.*hit_rate=([0-9.]+)%", float),
    ("matrix_hit_rate", r"Matrix Cache:.*hit_rate=([0-9.]+)%", float),
]

# Policy type extraction
POLICY_PATTERNS = [
    ("policy_type", r"Policy:\s+(.+?)(?:\n|$)", str),
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


def has_avx512_support() -> bool:
    """Check if CPU supports AVX-512"""
    flags = read_cpu_flags()
    avx512_flags = ["avx512f", "avx512bw", "avx512vl", "avx512dq"]
    return any(flag in flags for flag in avx512_flags)


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
    cpu_flags = read_cpu_flags()
    return {
        "timestamp_utc": utc_now(),
        "project_dir": str(project_dir),
        "python_version": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "uname": " ".join(platform.uname()),
        "cpu_model": read_first_cpu_model() or platform.processor() or "unknown",
        "cpu_flags": cpu_flags,
        "cpu_avx512_support": has_avx512_support(),
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


def parse_comprehensive_output(stdout: str) -> list[dict[str, Any]]:
    """Parse output from comprehensive_perf_test into structured records"""
    records = []
    current_record = {}

    for line in stdout.splitlines():
        # Try all patterns
        for key, pattern, caster in COMPREHENSIVE_PATTERNS + POLICY_PATTERNS:
            match = re.search(pattern, line)
            if match:
                try:
                    value = caster(match.group(1))
                    current_record[key] = value
                except (ValueError, IndexError):
                    pass

        # When we hit certain markers, save the current record
        if "Policy:" in line or "MLWE Sign:" in line:
            if current_record and "sign_ms" in current_record:
                records.append(current_record.copy())
                # Keep security level and cache info for next record
                keep_keys = ["security_level", "avx512_enabled", "keygen_attr_count"]
                current_record = {k: v for k, v in current_record.items() if k in keep_keys}

    # Save final record
    if current_record:
        records.append(current_record)

    return records


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
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def summarize_records(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate summary statistics across all benchmark records"""
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Comprehensive PABS-CRF benchmark with all optimizations"
    )
    parser.add_argument("--rounds", type=int, default=10, help="Number of test rounds (default: 10)")
    parser.add_argument(
        "--test-avx512",
        action="store_true",
        help="Test both with and without AVX-512 (if CPU supports it)",
    )
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--timeout-sec", type=int, default=600, help="Timeout per test run (default: 600s)")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    project_dir = PROJECT_DIR
    out_dir = args.out_dir or project_dir / "test-results" / "comprehensive" / local_stamp()
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

    # Determine which feature configurations to test
    test_configs = [
        {"name": "baseline", "features": ""},
    ]

    if args.test_avx512 and environment.get("cpu_avx512_support"):
        test_configs.append({"name": "avx512", "features": "avx512"})
        print("✓ CPU supports AVX-512, will test both baseline and avx512")
    elif args.test_avx512:
        print("✗ CPU does not support AVX-512, testing baseline only")

    all_records = []

    for config in test_configs:
        config_name = config["name"]
        features = config["features"]

        print(f"\n{'='*70}")
        print(f"Testing Configuration: {config_name.upper()}")
        if features:
            print(f"Features: {features}")
        print(f"{'='*70}\n")

        env = os.environ.copy()

        # Build
        if not args.skip_build:
            build_cmd = ["cargo", "build", "--release", "--example", "comprehensive_perf_test"]
            if features:
                build_cmd += ["--features", features]

            print(f"Building with config: {config_name}...")
            build_res = run_command(build_cmd, project_dir, env=env, timeout=300)
            write_text(logs_dir / f"build_{config_name}.stdout.log", build_res["stdout"])
            write_text(logs_dir / f"build_{config_name}.stderr.log", build_res["stderr"])

            if build_res["returncode"] != 0:
                print(f"✗ Build failed for {config_name}")
                write_json(out_dir / f"summary_{config_name}.json",
                          {"status": "build_failed", "build": build_res})
                continue
            print(f"✓ Build successful for {config_name}")

        # Run benchmark rounds
        for round_no in range(1, args.rounds + 1):
            print(f"[{config_name}] Round {round_no}/{args.rounds} ", end="", flush=True)

            run_cmd = ["cargo", "run", "--release", "--example", "comprehensive_perf_test"]
            if features:
                run_cmd += ["--features", features]

            res = run_command(run_cmd, project_dir, env=env, timeout=args.timeout_sec)

            log_prefix = f"{config_name}_round_{round_no:02d}"
            write_text(logs_dir / f"{log_prefix}.stdout.log", res["stdout"])
            write_text(logs_dir / f"{log_prefix}.stderr.log", res["stderr"])

            if res["returncode"] != 0:
                print(f"✗ FAILED")
                append_jsonl(out_dir / f"errors_{config_name}.jsonl", {
                    "round": round_no,
                    "config": config_name,
                    "exit_code": res["returncode"],
                    "duration_sec": res["duration_sec"],
                })
                continue

            # Parse results
            records = parse_comprehensive_output(res["stdout"])
            for record in records:
                record["round"] = round_no
                record["config"] = config_name
                record["features"] = features
                record["command_duration_sec"] = res["duration_sec"]
                all_records.append(record)
                append_jsonl(out_dir / f"records_{config_name}.jsonl", record)

            print(f"✓ OK ({len(records)} records)")

    # Write combined results
    write_csv(out_dir / "all_records.csv", all_records)

    # Generate summary
    summary = {
        "status": "completed",
        "generated_at_utc": utc_now(),
        "rounds": args.rounds,
        "configs_tested": [c["name"] for c in test_configs],
        "total_records": len(all_records),
        "metrics": summarize_records(all_records),
    }

    # Per-config summaries
    for config in test_configs:
        config_name = config["name"]
        config_records = [r for r in all_records if r.get("config") == config_name]
        summary[f"metrics_{config_name}"] = summarize_records(config_records)

    write_json(out_dir / "summary.json", summary)

    # Generate readable summary CSV
    summary_rows = []
    for metric, stats in summary["metrics"].items():
        if stats.get("count", 0) > 0:
            summary_rows.append({
                "metric": metric,
                "count": stats["count"],
                "mean": stats["mean"],
                "stdev": stats["stdev"],
                "median": stats.get("median"),
                "min": stats["min"],
                "max": stats["max"],
            })
    write_csv(out_dir / "summary_metrics.csv", summary_rows)

    print(f"\n{'='*70}")
    print(f"✓ All tests complete!")
    print(f"Results written to: {out_dir}")
    print(f"Total records collected: {len(all_records)}")
    print(f"{'='*70}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
