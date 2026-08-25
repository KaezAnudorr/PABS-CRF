#!/usr/bin/env python3
"""Aggregate cross-platform benchmark JSON results into a LaTeX comparison table."""

import json
import sys
import argparse
from pathlib import Path


def load_results(files):
    docs = []
    for f in files:
        p = Path(f)
        if not p.exists():
            print(f"WARNING: {f} not found, skipping", file=sys.stderr)
            continue
        with open(p, encoding="utf-8") as fh:
            docs.append(json.load(fh))
    return docs


def platform_label(doc):
    plat = doc.get("platform", {})
    arch = plat.get("arch", "unknown")
    cpu = plat.get("cpu", "unknown")
    short_cpu = cpu.split("@")[0].strip() if "@" in cpu else cpu
    if len(short_cpu) > 30:
        short_cpu = short_cpu[:28] + ".."
    feat = plat.get("cpu_features", [])
    feat_str = ""
    if "avx512f" in feat:
        feat_str = "+AVX512"
    elif "avx2" in feat:
        feat_str = "+AVX2"
    elif "neon" in feat:
        feat_str = "+NEON"
    elif "sve" in feat:
        feat_str = "+SVE"
    return f"{arch} {feat_str}"


def collect_bench_names(docs):
    names = []
    seen = set()
    for doc in docs:
        for name in doc.get("results", {}):
            if name not in seen:
                names.append(name)
                seen.add(name)
    return names


def fmt_us(val):
    if val >= 1000:
        return f"{val/1000:.2f} ms"
    return f"{val:.1f} $\\mu$s"


def fmt_ci(lo, hi):
    return f"[{fmt_us(lo)}, {fmt_us(hi)}]"


def generate_latex_table(docs):
    bench_names = collect_bench_names(docs)
    if not bench_names:
        print("No benchmark results found.", file=sys.stderr)
        return ""

    col_count = 1 + len(docs)
    col_spec = "l" + "r" * len(docs)

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"  \centering")
    lines.append(r"  \caption{Cross-Platform Benchmark Comparison}")
    lines.append(r"  \label{tab:cross-platform-bench}")
    lines.append(f"  \\begin{{tabular}}{{{col_spec}}}")
    lines.append(r"    \toprule")

    header = "Benchmark"
    for doc in docs:
        header += f" & {platform_label(doc)}"
    header += r" \\"
    lines.append(f"    {header}")
    lines.append(r"    \midrule")

    for name in bench_names:
        row = name.replace("_", r"\_")
        for doc in docs:
            res = doc.get("results", {}).get(name)
            if res:
                mean = res.get("mean_us", 0)
                lo = res.get("ci_low_us", 0)
                hi = res.get("ci_high_us", 0)
                row += f" & {fmt_us(mean)} {fmt_ci(lo, hi)}"
            else:
                row += " & ---"
        row += r" \\"
        lines.append(f"    {row}")

    lines.append(r"    \bottomrule")
    lines.append(r"  \end{tabular}")

    notes = []
    for i, doc in enumerate(docs):
        plat = doc.get("platform", {})
        rust_v = doc.get("rust_version", "?")
        ss = doc.get("sample_size", "?")
        cpu = plat.get("cpu", "unknown")
        ram = plat.get("ram_gb", "?")
        notes.append(f"Col {i+1}: {cpu}, {ram}GB RAM, Rust {rust_v}, n={ss}")

    lines.append(r"  \vspace{0.5em}")
    lines.append(r"  {\small " + "; ".join(notes) + r"}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate cross-platform benchmark JSON results into a LaTeX table"
    )
    parser.add_argument(
        "files", nargs="+", help="JSON result files from cross_platform_bench.sh"
    )
    parser.add_argument(
        "--output", "-o", default=None, help="Output file (default: stdout)"
    )
    args = parser.parse_args()

    docs = load_results(args.files)
    if not docs:
        print("ERROR: no valid result files loaded", file=sys.stderr)
        sys.exit(1)

    latex = generate_latex_table(docs)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(latex + "\n")
        print(f"LaTeX table written to {args.output}", file=sys.stderr)
    else:
        print(latex)


if __name__ == "__main__":
    main()
