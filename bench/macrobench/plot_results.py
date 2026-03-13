import re
import os
import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

# Usage: python plot_results.py
# Tries to plot both results-baseline.csv and results-rebound.csv side-by-side.
# Produces per-workload subplots with grouped bars by operation (baseline vs rebound) and saves to latencies-comparison.pdf.


def load_results(base: Path) -> dict:
    paths = {
        "baseline": base / "results-baseline.csv",
        "rebound": base / "results-rebound.csv",
    }
    dfs = {}
    for mode, p in paths.items():
        if p.exists():
            df = pd.read_csv(p)
            # Normalize numeric columns
            df["total_s"] = pd.to_numeric(df.get("total_s", pd.NA), errors="coerce")
            df["job_s"] = pd.to_numeric(df.get("job_s", pd.NA), errors="coerce")
            dfs[mode] = df
    if not dfs:
        # Fall back to legacy results.csv if present
        legacy = base / "results.csv"
        if legacy.exists():
            df = pd.read_csv(legacy)
            df["total_s"] = pd.to_numeric(df.get("total_s", pd.NA), errors="coerce")
            df["job_s"] = pd.to_numeric(df.get("job_s", pd.NA), errors="coerce")
            dfs["results"] = df
        else:
            raise SystemExit(
                f"No results CSV found in {base}. Expected results-baseline.csv and/or results-rebound.csv (or results.csv)."
            )
    return dfs


def workloads_from_df(df: pd.DataFrame) -> list:
    labels = df["label"].dropna().unique().tolist()
    wset = []
    # Accept any phase suffix of one or more letters (A, B, C, etc.)
    pat = re.compile(r"^(?P<w>.+)_(?P<phase>[A-Za-z]+)$")
    for lab in sorted(labels):
        m = pat.match(str(lab))
        if m:
            w = m.group("w")
            if w not in wset:
                wset.append(w)
    return wset


def extract_op_latencies(df: pd.DataFrame, workload: str) -> dict:
    # Map operations to their expected phase labels
    phase_for_op = {
        "build": "A",
        "create_snapshot": "A",
        "rollback_snapshot": "B",
        "prune_snapshot": "C",
        "audit_lineage": "C",
    }

    def get_job_latency(phase: str, job_name: str) -> float:
        label = f"{workload}_{phase}"
        subset = df[(df["label"] == label) & (df["job_name"] == job_name)]
        if subset.empty:
            return 0.0
        # Average across multiple trials/rows
        vals = pd.to_numeric(subset["job_s"], errors="coerce")
        m = float(vals.mean(skipna=True)) if not vals.empty else 0.0
        return m if pd.notna(m) else 0.0

    def get_job_latency_candidates(phase: str, candidates: list[str], regex: str | None = None) -> float:
        label = f"{workload}_{phase}"
        sdf = df[df["label"] == label]
        for name in candidates:
            sub = sdf[sdf["job_name"] == name]
            if not sub.empty:
                # Average across multiple trials/rows
                vals = pd.to_numeric(sub["job_s"], errors="coerce")
                m = float(vals.mean(skipna=True)) if not vals.empty else 0.0
                return m if pd.notna(m) else 0.0
        if regex:
            sub = sdf[sdf["job_name"].astype(str).str.contains(regex, regex=True, na=False)]
            if not sub.empty:
                vals = pd.to_numeric(sub["job_s"], errors="coerce")
                m = float(vals.mean(skipna=True)) if not vals.empty else 0.0
                return m if pd.notna(m) else 0.0
        return 0.0

    # Build is commonly named per-workload (e.g., "sample_build", "llama2_build").
    build_latency = get_job_latency_candidates(
        phase="A",
        candidates=[f"{workload}_build", "build"],
        regex=r"_build$",
    )

    # Deploy job is common across modes
    deploy_a = get_job_latency("A", "deploy_k8s")
    deploy_b = get_job_latency("B", "deploy_k8s")
    # State update job is workload-specific (e.g., sample_state_update, etc.)
    st_a = get_job_latency_candidates("A", [f"{workload}_state_update", "state_update"], regex=r"_state_update$")

    rb_snap = get_job_latency("B", "rollback_snapshot")
    return {
        "build": build_latency,
        "deploy_A": deploy_a,
        "deploy_B": deploy_b,
        "state_update": st_a,
        "create_release": get_job_latency("A", "create_release"),
        "create_snapshot": get_job_latency("A", "create_snapshot"),
        "rollback_snapshot": rb_snap,
        "rollback_release": get_job_latency("B", "rollback_release"),
        "prune_snapshot": get_job_latency("C", "prune_snapshot"),
        "prune_release": get_job_latency("C", "prune_release"),
        "audit_lineage": get_job_latency("C", "audit_lineage"),
    }


def compute_e2e_push(df: pd.DataFrame, workload: str, mode: str) -> float:
    """
    End-to-end push path per pipeline A:
    - baseline: build + deploy_k8s
    - rebound:  build + deploy_k8s + state_update
    """
    ops = extract_op_latencies(df, workload)
    total = (ops.get("build", 0.0) or 0.0) + (ops.get("deploy_A", 0.0) or 0.0)
    # Only add state_update if present (typical for rebound)
    st = ops.get("state_update", 0.0) or 0.0
    # Heuristic: if mode looks like rebound, include state_update; otherwise include only if present>0
    if mode == "rebound" or st > 0:
        total += st
    return float(total)


def compute_e2e_rollback(df: pd.DataFrame, workload: str, mode: str) -> float:
    """
    End-to-end rollback path per pipeline B:
    - baseline: rollback_release job duration (includes rollout)
    - rebound:  rollback_snapshot job duration (includes rollout)
    """
    ops = extract_op_latencies(df, workload)
    if mode == "baseline":
        return float(ops.get("rollback_release", 0.0) or 0.0)
    # default to rebound behavior (rollback_snapshot)
    return float(ops.get("rollback_snapshot", 0.0) or 0.0)


def main():
    # Accept a target directory like the microbench plot script. If not provided,
    # default to $REBOUND_HOME/o when available; otherwise, use the script's directory.
    parser = argparse.ArgumentParser(description="Plot macrobench results CSVs")
    parser.add_argument(
        "dir",
        nargs="?",
        help="Directory containing results-baseline.csv and/or results-rebound.csv (e.g., .../o)",
    )
    args = parser.parse_args()

    if args.dir:
        base = Path(args.dir).resolve()
    else:
        rh = os.environ.get("REBOUND_HOME")
        base = Path(rh, "o").resolve() if rh else Path(__file__).parent
    dfs = load_results(base)

    # Determine workloads across all available modes
    all_workloads = []
    for df in dfs.values():
        for w in workloads_from_df(df):
            if w not in all_workloads:
                all_workloads.append(w)
    if not all_workloads:
        raise SystemExit("No workload labels found (expected labels like 'sample_A', 'llama2_B', ...)")
    # Style: larger fonts globally
    plt.rcParams.update({"font.size": 18})

    # Use default matplotlib color cycle
    prop_cycle = plt.rcParams['axes.prop_cycle']
    default_colors = prop_cycle.by_key()['color']
    colors = {"baseline": default_colors[0], "rebound": default_colors[1]}
    mode_hatch = {"baseline": "///", "rebound": "\\\\"}
    modes_present = [m for m in ("baseline", "rebound") if m in dfs] or list(dfs.keys())

    # Figure 1: build latency grouped by workload (baseline vs rebound)
    # Ops for the per-workload ops chart (Figure 2). Drop baseline-specific release/prune
    # and omit rollback_snapshot (covered separately in E2E rollback chart).
    ops_other = ["create_snapshot", "prune_snapshot", "audit_lineage"]
    fig_build, ax = plt.subplots(1, 1, figsize=(6, 2.5), constrained_layout=True)
    x = list(range(len(all_workloads)))
    width = 0.35 if len(modes_present) >= 2 else 0.6

    for j, mode in enumerate([m for m in ("baseline", "rebound") if m in dfs] or list(dfs.keys())):
        offset = (j - ((len(modes_present) - 1) / 2)) * width
        vals = []
        for w in all_workloads:
            vals.append(extract_op_latencies(dfs[mode], w).get("build", 0.0))
        bars = ax.bar(
            [i + offset for i in x],
            vals,
            width=width,
            label=mode,
            color=colors.get(mode),
            edgecolor="black",
            linewidth=1.0,
        )
        for rect in bars.patches:
            rect.set_hatch(mode_hatch.get(mode, ""))

    ax.set_title("Build latency by workload", pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(all_workloads)
    ax.set_ylabel("Latency (s)")
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(title="", loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.225), borderaxespad=0.2)
    out_build = base / "latencies-build.pdf"
    plt.savefig(out_build, format="pdf", bbox_inches="tight")
    print(f"Saved build chart to {out_build}")
    plt.close(fig_build)

    # Figure 2: Grouped bar chart for operations (x=workload, grouped by operation, Rebound-only)
    fig_ops, ax_ops = plt.subplots(1, 1, figsize=(9, 3), constrained_layout=True)
    
    preferred_mode = "rebound" if "rebound" in dfs else (next(iter(dfs.keys())))
    
    x = list(range(len(all_workloads)))
    width = 0.25  # width per operation bar
    num_ops = len(ops_other)
    
    # Use default matplotlib color cycle for operations
    prop_cycle = plt.rcParams['axes.prop_cycle']
    default_colors = prop_cycle.by_key()['color']
    op_hatch = {
        "create_snapshot": "///",
        "prune_snapshot": "\\\\\\",
        "audit_lineage": "xxx"
    }
    
    for op_idx, op in enumerate(ops_other):
        offset = (op_idx - (num_ops - 1) / 2) * width
        vals = [extract_op_latencies(dfs[preferred_mode], w).get(op, 0.0) for w in all_workloads]
        bars = ax_ops.bar(
            [i + offset for i in x],
            vals,
            width=width,
            label=op.replace("_", " "),
            color=default_colors[op_idx % len(default_colors)],
            edgecolor="black",
            linewidth=1.0,
        )
        for rect in bars.patches:
            rect.set_hatch(op_hatch.get(op, ""))
        
        # Annotate N/A for zero/NaN values
        for xi, v in zip(x, vals):
            try:
                fv = float(v)
            except Exception:
                fv = 0.0
            if not pd.notna(v) or fv <= 0.0:
                ax_ops.text(xi + offset, 0.02, "N/A", ha="center", va="bottom", rotation=90, fontsize=8)
    
    ax_ops.set_title("Operation latencies by workload", pad=20)
    ax_ops.set_xticks(x)
    ax_ops.set_xticklabels(all_workloads)
    ax_ops.set_ylabel("Latency (s)")
    ax_ops.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax_ops.spines["top"].set_visible(False)
    ax_ops.spines["right"].set_visible(False)
    ax_ops.legend(title="", loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.175), borderaxespad=0.2)

    out_ops = base / "latencies-ops.pdf"
    plt.savefig(out_ops, format="pdf", bbox_inches="tight")
    print(f"Saved non-build ops chart to {out_ops}")
    plt.close(fig_ops)

    # Figure 3: E2E push (build+deploy[+state_update]) baseline vs rebound
    fig_push, ax_push = plt.subplots(1, 1, figsize=(6, 2.5), constrained_layout=True)
    x = list(range(len(all_workloads)))
    width = 0.35 if len(modes_present) >= 2 else 0.6
    for j, mode in enumerate([m for m in ("baseline", "rebound") if m in dfs] or list(dfs.keys())):
        offset = (j - ((len(modes_present) - 1) / 2)) * width
        vals = []
        for w in all_workloads:
            vals.append(compute_e2e_push(dfs[mode], w, mode))
        bars = ax_push.bar(
            [i + offset for i in x],
            vals,
            width=width,
            label=mode,
            color=colors.get(mode),
            edgecolor="black",
            linewidth=1.0,
        )
        for rect in bars.patches:
            rect.set_hatch(mode_hatch.get(mode, ""))
    # ax_push.set_title("build + deploy (+ state_update) latency", fontsize=18)
    ax_push.set_title("build + deploy latency", fontsize=18, pad=20)
    ax_push.set_xticks(x)
    ax_push.set_xticklabels(all_workloads)
    ax_push.set_ylabel("Latency (s)")
    ax_push.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax_push.spines["top"].set_visible(False)
    ax_push.spines["right"].set_visible(False)
    ax_push.legend(title="", loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.225), borderaxespad=0.2)
    out_push = base / "latencies-e2e-push.pdf"
    plt.savefig(out_push, format="pdf", bbox_inches="tight")
    print(f"Saved E2E push chart to {out_push}")
    plt.close(fig_push)

    # Figure 4: E2E rollback (deploy [+ rollback]) baseline vs rebound
    fig_rb, ax_rb = plt.subplots(1, 1, figsize=(6, 2.5), constrained_layout=True)
    x = list(range(len(all_workloads)))
    width = 0.35 if len(modes_present) >= 2 else 0.6
    for j, mode in enumerate([m for m in ("baseline", "rebound") if m in dfs] or list(dfs.keys())):
        offset = (j - ((len(modes_present) - 1) / 2)) * width
        vals = []
        for w in all_workloads:
            vals.append(compute_e2e_rollback(dfs[mode], w, mode))
        bars = ax_rb.bar(
            [i + offset for i in x],
            vals,
            width=width,
            label=mode,
            color=colors.get(mode),
            edgecolor="black",
            linewidth=1.0,
        )
        for rect in bars.patches:
            rect.set_hatch(mode_hatch.get(mode, ""))
    # ax_rb.set_title("rollback + deploy latency")
    ax_rb.set_title("rollback latency", pad=20)
    ax_rb.set_xticks(x)
    ax_rb.set_xticklabels(all_workloads)
    ax_rb.set_ylabel("Latency (s)")
    ax_rb.grid(True, axis="y", linestyle="--", alpha=0.3)
    ax_rb.spines["top"].set_visible(False)
    ax_rb.spines["right"].set_visible(False)
    ax_rb.legend(title="", loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.225), borderaxespad=0.2)
    out_rb = base / "latencies-e2e-rollback.pdf"
    plt.savefig(out_rb, format="pdf", bbox_inches="tight")
    print(f"Saved E2E rollback chart to {out_rb}")
    plt.close(fig_rb)


if __name__ == "__main__":
    main()
