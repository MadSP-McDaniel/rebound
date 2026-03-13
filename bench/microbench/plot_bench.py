import argparse
import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

sns.set_style("whitegrid")

# Use a uniform, compact font size across titles, labels, ticks, and legends.
plt.rcParams.update({
    "font.size": 9,
    "axes.titlesize": 9,
    "axes.labelsize": 9,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dir", help="Directory containing benchmark CSVs (e.g., .../o/micro)")
    parser.add_argument("--prefix", default="plots", help="Filename prefix for output figures in the same directory")
    # Note: obj-bytes can be entirely simulated based on actual object size (doesnt need to match whatever was passed in to the go run command); default 1 byte is just for modeling
    parser.add_argument("--obj-bytes", type=int, default=1, help="Bytes per object payload (for modeling)")
    parser.add_argument("--prune-keep", type=int, default=20, help="Number of snapshots to keep (for modeling)")
    args = parser.parse_args()

    out_dir = os.path.abspath(args.dir)
    if not os.path.isdir(out_dir):
        raise SystemExit(f"Not a directory: {out_dir}")

    def load_csv(name):
        p = os.path.join(out_dir, name)
        if os.path.exists(p):
            df = pd.read_csv(p)
            if "bytes" in df.columns:
                df["mb"] = df["bytes"].astype(float) / (1024 * 1024)
            return df
        return None

    written = []

    # 1) ops_vs_n.csv -> operation latency vs N
    df = load_csv("ops_vs_n.csv")
    if df is not None and not df.empty:
        fig, ax = plt.subplots(1, 1, figsize=(4, 2))
        ops = ["update", "snapshot", "rollback", "prune"]
        sdf = df[df["metric"].isin(ops)].copy()
        if not sdf.empty:
            # aggregate median per (metric, n)
            sdf = sdf.groupby(["metric", "n"], as_index=False)["millis"].median()
            # Convert to seconds if max > 1000ms
            use_seconds = sdf["millis"].max() > 1000
            if use_seconds:
                sdf["latency"] = sdf["millis"] / 1000.0
                ylabel = "Latency (s)"
            else:
                sdf["latency"] = sdf["millis"]
                ylabel = "Latency (ms)"
            sns.lineplot(ax=ax, data=sdf, x="n", y="latency", hue="metric", style="metric", markers=True, dashes=True, markersize=8)
            ax.set_title("Operation latency vs. state size")
            ax.set_xlabel("Number of objects (N)")
            ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0)
            ax.legend(title=None, ncol=2, loc="best")
            fig.tight_layout()
            outp = os.path.join(out_dir, f"{args.prefix}_ops_vs_n_latency_ops.pdf")
            fig.savefig(outp, dpi=200, bbox_inches="tight")
            written.append(outp)
        plt.close(fig)

    # 2) ops_vs_updates.csv -> latency vs updates for all operations combined
    df = load_csv("ops_vs_updates.csv")
    if df is not None and not df.empty and "tree_size" in df.columns:
        # Plot all operations together since they're in similar range (2-4s)
        all_ops = ["update", "rollback", "snapshot", "prune"]
        sdf_all = df[df["metric"].isin(all_ops)].copy()
        if not sdf_all.empty:
            fig, ax = plt.subplots(1, 1, figsize=(4, 2))
            # median per (metric, n, tree_size)
            lat_all = sdf_all.groupby(["metric", "n", "tree_size"], as_index=False)["millis"].median()
            # Convert to seconds if max > 1000ms
            use_seconds = lat_all["millis"].max() > 1000
            if use_seconds:
                lat_all["latency"] = lat_all["millis"] / 1000.0
                ylabel = "Latency (s)"
            else:
                lat_all["latency"] = lat_all["millis"]
                ylabel = "Latency (ms)"
            # Create combined hue column for metric and n
            # lat_all["op_n"] = lat_all["metric"] + " (n=" + lat_all["n"].astype(str) + ")"
            lat_all["op_n"] = lat_all["metric"]
            sns.lineplot(ax=ax, data=lat_all, x="tree_size", y="latency", hue="op_n", style="op_n", markers=True, dashes=True, markersize=8)
            ax.set_title("Per-object operation latency vs. PAD size")
            ax.set_xlabel("PAD size (number of leaves)")
            ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0)
            ax.legend(title=None, ncol=2, loc="upper left")
            fig.tight_layout()
            outp = os.path.join(out_dir, f"{args.prefix}_ops_lat_vs_num_updates.pdf")
            fig.savefig(outp, dpi=200, bbox_inches="tight")
            written.append(outp)
            plt.close(fig)

    # 3) storage_vs_n.csv -> storage vs N
    df = load_csv("storage_vs_n.csv")
    if df is not None and not df.empty and "mb" in df.columns:
        fig, ax = plt.subplots(1, 1, figsize=(4, 2))
        s2 = df.groupby(["n"], as_index=False)["mb"].median()
        sns.lineplot(ax=ax, data=s2, x="n", y="mb", marker="o", markersize=8)
        ax.set_title("Storage vs. State Size")
        ax.set_xlabel("Number of objects (N)")
        ax.set_ylabel("Storage (MB)")
        ax.set_ylim(bottom=0)
        fig.tight_layout()
        outp = os.path.join(out_dir, f"{args.prefix}_storage_vs_n.pdf")
        fig.savefig(outp, dpi=200, bbox_inches="tight")
        written.append(outp)
        plt.close(fig)

    # 4) storage_vs_updates.csv -> storage vs updates (hue by N)
    df = load_csv("storage_vs_updates.csv")
    if df is not None and not df.empty and "tree_size" in df.columns and "mb" in df.columns:
        fig, ax = plt.subplots(1, 1, figsize=(4, 2))
        upd = df.groupby(["n", "tree_size"], as_index=False)["mb"].median()
        sns.lineplot(ax=ax, data=upd, x="tree_size", y="mb", hue="n", style="n", markers=True, dashes=True, markersize=8)
        ax.set_title("Storage vs. PAD size")
        ax.set_xlabel("PAD size (number of leaves)")
        ax.set_ylabel("Storage (MB)")
        ax.set_ylim(bottom=0)
        # Relabel legend entries from raw n values to "n=<val>"
        handles, labels = ax.get_legend_handles_labels()
        pretty = []
        for lab in labels:
            try:
                v = int(float(lab))
                pretty.append(f"n={v}")
            except Exception:
                pretty.append(lab)
        ax.legend(handles, pretty, title=None, ncol=2, loc="best")
        fig.tight_layout()
        outp = os.path.join(out_dir, f"{args.prefix}_storage_vs_num_updates.pdf")
        fig.savefig(outp, dpi=200, bbox_inches="tight")
        written.append(outp)
        plt.close(fig)

    # 5) query_vs_n.csv -> query latency per key vs N
    df = load_csv("query_vs_n.csv")
    if df is not None and not df.empty:
        fig, ax = plt.subplots(1, 1, figsize=(4, 2))
        queries = ["query_reconstruct", "query_ovm"]
        sdf = df[df["metric"].isin(queries)].copy()
        if not sdf.empty:
            sdf = sdf.groupby(["metric", "n"], as_index=False)["millis"].median()
            # Convert to seconds if max > 1000ms
            use_seconds = sdf["millis"].max() > 1000
            if use_seconds:
                sdf["latency"] = sdf["millis"] / 1000.0
                ylabel = "Latency (s per key)"
            else:
                sdf["latency"] = sdf["millis"]
                ylabel = "Latency (ms per key)"
            sns.lineplot(ax=ax, data=sdf, x="n", y="latency", hue="metric", marker="o", markersize=8)
            ax.set_title("Query latency per key vs. state size")
            ax.set_xlabel("Number of objects (N)")
            ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0)
            ax.legend(title=None, ncol=2, loc="best")
            fig.tight_layout()
            outp = os.path.join(out_dir, f"{args.prefix}_query_vs_n.pdf")
            fig.savefig(outp, dpi=200, bbox_inches="tight")
            written.append(outp)
        plt.close(fig)


    # 7) query_vs_updates.csv -> query latency per key vs number of updates (history length)
    df = load_csv("query_vs_updates.csv")
    if df is not None and not df.empty and "tree_size" in df.columns:
        # Split into two plots: query_reconstruct (high latency) and query_ovm (low latency)
        
        # Plot 7a: query_reconstruct
        sdf_reconstruct = df[df["metric"] == "query_reconstruct"].copy()
        if not sdf_reconstruct.empty:
            fig, ax = plt.subplots(1, 1, figsize=(4, 2))
            # aggregate median per tree_size
            sdf_reconstruct = sdf_reconstruct.groupby(["tree_size"], as_index=False)["millis"].median()
            # Convert to seconds if max > 1000ms
            use_seconds = sdf_reconstruct["millis"].max() > 1000
            if use_seconds:
                sdf_reconstruct["latency"] = sdf_reconstruct["millis"] / 1000.0
                ylabel = "Latency (s per key)"
            else:
                sdf_reconstruct["latency"] = sdf_reconstruct["millis"]
                ylabel = "Latency (ms per key)"
            sns.lineplot(ax=ax, data=sdf_reconstruct, x="tree_size", y="latency", marker="o", markersize=8, color="C0")
            ax.set_title("Reconstruct query latency vs. PAD size")
            ax.set_xlabel("PAD size (number of leaves)")
            ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0)
            fig.tight_layout()
            outp = os.path.join(out_dir, f"{args.prefix}_query_reconstruct_vs_num_updates.pdf")
            fig.savefig(outp, dpi=200, bbox_inches="tight")
            written.append(outp)
            plt.close(fig)
        
        # Plot 7b: query_ovm
        sdf_ovm = df[df["metric"] == "query_ovm"].copy()
        if not sdf_ovm.empty:
            fig, ax = plt.subplots(1, 1, figsize=(4, 2))
            # aggregate median per tree_size
            sdf_ovm = sdf_ovm.groupby(["tree_size"], as_index=False)["millis"].median()
            # Convert to seconds if max > 1000ms
            use_seconds = sdf_ovm["millis"].max() > 1000
            if use_seconds:
                sdf_ovm["latency"] = sdf_ovm["millis"] / 1000.0
                ylabel = "Latency (s per key)"
            else:
                sdf_ovm["latency"] = sdf_ovm["millis"]
                ylabel = "Latency (ms per key)"
            sns.lineplot(ax=ax, data=sdf_ovm, x="tree_size", y="latency", marker="s", markersize=8, color="C1")
            ax.set_title("OVM query latency vs. PAD size")
            ax.set_xlabel("PAD size (number of leaves)")
            ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0)
            fig.tight_layout()
            outp = os.path.join(out_dir, f"{args.prefix}_query_ovm_vs_num_updates.pdf")
            fig.savefig(outp, dpi=200, bbox_inches="tight")
            written.append(outp)
            plt.close(fig)

    # 8) ops_vs_updates_with_pruning.csv -> latency and storage vs updates with pruning
    df = load_csv("ops_vs_updates_with_pruning.csv")
    if df is not None and not df.empty and "tree_size" in df.columns and "mb" in df.columns:
        # One plot per 'n' value
        for n_val in df["n"].unique():
            sdf = df[df["n"] == n_val].copy()
            if sdf.empty:
                continue

            fig, ax1 = plt.subplots(1, 1, figsize=(4, 2))

            # Plot latency on primary axis
            lat = sdf.groupby(["tree_size"], as_index=False)["millis"].median()
            # Convert to seconds if max > 1000ms
            use_seconds = lat["millis"].max() > 1000
            if use_seconds:
                lat["latency"] = lat["millis"] / 1000.0
                ylabel1 = "Latency (s)"
                label1 = "Update Latency (s)"
            else:
                lat["latency"] = lat["millis"]
                ylabel1 = "Latency (ms)"
                label1 = "Update Latency (ms)"
            sns.lineplot(ax=ax1, data=lat, x="tree_size", y="latency", color="C0", label=label1, marker="o", markersize=5)
            ax1.set_xlabel("PAD size (number of leaves)")
            ax1.set_ylabel(ylabel1, color="C0")
            ax1.tick_params(axis='y', labelcolor="C0")
            ax1.set_ylim(bottom=0)

            # Plot storage on secondary axis
            ax2 = ax1.twinx()
            stor = sdf.groupby(["tree_size"], as_index=False)["mb"].median()
            sns.lineplot(ax=ax2, data=stor, x="tree_size", y="mb", color="C1", label="Storage (MB)", marker="s", markersize=5)
            ax2.set_ylabel("Storage (MB)", color="C1")
            ax2.tick_params(axis='y', labelcolor="C1")
            ax2.set_ylim(bottom=0)

            # Combine legends
            lines, labels = ax1.get_legend_handles_labels()
            lines2, labels2 = ax2.get_legend_handles_labels()
            ax2.legend(lines + lines2, labels + labels2, loc='upper left')
            ax1.get_legend().remove()

            ax1.set_title(f"Latency and Storage vs. PAD size (n={n_val})")
            fig.tight_layout()
            outp = os.path.join(out_dir, f"{args.prefix}_pruning_impact_n{n_val}.pdf")
            fig.savefig(outp, dpi=200, bbox_inches="tight")
            written.append(outp)
            plt.close(fig)

    # 9) ops_vs_updates_with_pruning.csv -> TOTAL storage vs updates with pruning (modeled)
    df = load_csv("ops_vs_updates_with_pruning.csv")
    if df is not None and not df.empty and "tree_size" in df.columns and "mb" in df.columns:
        # One plot per 'n' value
        for n_val in df["n"].unique():
            sdf = df[df["n"] == n_val].copy()
            if sdf.empty:
                continue

            # Model raw object storage cost based on the pruning window
            # Active snapshots grow until they hit the prune_keep limit
            sdf['active_snapshots'] = sdf['n_updates'].apply(lambda u: min(u, args.prune_keep))
            # Raw storage = active_snapshots * num_objects * bytes_per_object
            raw_bytes = sdf['active_snapshots'] * n_val * args.obj_bytes
            sdf['raw_storage_mb'] = raw_bytes / (1024 * 1024)
            # Total storage = measured metadata + modeled raw object storage
            sdf['total_storage_mb'] = sdf['mb'] + sdf['raw_storage_mb']

            fig, ax = plt.subplots(1, 1, figsize=(4, 2))

            # Aggregate medians for plotting
            plot_df = sdf.groupby("tree_size", as_index=False).median(numeric_only=True)

            # Plot modeled Total System Storage
            sns.lineplot(ax=ax, data=plot_df, x="tree_size", y="total_storage_mb", color="C2", label="Metadata+Data Storage", marker="o", markersize=5)

            # Plot measured Metadata Storage for comparison
            sns.lineplot(ax=ax, data=plot_df, x="tree_size", y="mb", color="C1", label="Metadata Storage", marker="s", markersize=5, linestyle="--")

            ax.set_xlabel("PAD size (number of leaves)")
            ax.set_ylabel("Storage (MB)")
            ax.set_ylim(bottom=0)
            ax.legend(title=None, loc='best')
            ax.set_title(f"Total System Storage vs. PAD size (n={n_val})")
            fig.tight_layout()
            outp = os.path.join(out_dir, f"{args.prefix}_total_storage_pruning_impact_n{n_val}.pdf")
            fig.savefig(outp, dpi=200, bbox_inches="tight")
            written.append(outp)
            plt.close(fig)

    if written:
        print("Wrote:")
        for w in written:
            print(" ", w)
    else:
        print("No plots generated (no expected CSVs in directory)")


if __name__ == "__main__":
    main()
