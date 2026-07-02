#!/usr/bin/env python3
"""
analyze_results.py — CND Project Statistical Analysis & Visualization
Reads CSV files from simulate_attacks.sh and collect_metrics.sh.
Generates:
  - Summary statistics (mean, median, stddev)
  - Bar charts: TPR/FPR by scenario across modes A/B/C
  - Detection latency charts
  - Overhead comparison charts
  - t-test: Mode B vs Mode C
  - LaTeX table for academic publication
"""

import csv
import json
import os
import statistics
import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    from scipy import stats as scipy_stats
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("WARNING: matplotlib/scipy not installed. Run: pip3 install matplotlib scipy numpy")

RESULTS_DIR = Path("evaluation/results")
CHARTS_DIR = RESULTS_DIR / "charts"
CHARTS_DIR.mkdir(parents=True, exist_ok=True)

COLORS = {
    'mode_a': '#e74c3c',   # Red — No Security
    'mode_b': '#f39c12',   # Orange — Build-time Only
    'mode_c': '#27ae60',   # Green — Full Framework
}


# ══════════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_detection_results() -> list:
    path = RESULTS_DIR / "detection_results.csv"
    if not path.exists():
        print(f"ERROR: {path} not found. Run simulate_attacks.sh first.")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def load_performance_results() -> list:
    path = RESULTS_DIR / "performance_results.csv"
    if not path.exists():
        print(f"ERROR: {path} not found. Run collect_metrics.sh first.")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def load_false_positive_results() -> list:
    path = RESULTS_DIR / "false_positive_results.csv"
    if not path.exists():
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


# ══════════════════════════════════════════════════════════════════════════════
# DETECTION ACCURACY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_detection(rows: list) -> dict:
    """Calculate TPR, FNR, detection latency per scenario."""
    by_scenario = {}

    for row in rows:
        s = row['scenario']
        if s not in by_scenario:
            by_scenario[s] = {
                'total': 0, 'detected': 0,
                'times': [], 'attack_type': row.get('attack_type', ''),
                'detection_layer': row.get('detection_layer', '')
            }
        by_scenario[s]['total'] += 1
        if row['detected'] == 'true':
            by_scenario[s]['detected'] += 1
            t = int(row['detection_time_ms'])
            if t > 0:
                by_scenario[s]['times'].append(t)

    results = {}
    for s, d in by_scenario.items():
        n = d['total']
        det = d['detected']
        times = d['times']

        results[s] = {
            'attack_type': d['attack_type'],
            'detection_layer': d['detection_layer'],
            'total_runs': n,
            'detected': det,
            'tpr': det / n if n > 0 else 0,
            'fnr': (n - det) / n if n > 0 else 0,
            'detection_latency': {
                'mean': statistics.mean(times) if times else 0,
                'median': statistics.median(times) if times else 0,
                'stdev': statistics.stdev(times) if len(times) > 1 else 0,
                'min': min(times) if times else 0,
                'max': max(times) if times else 0,
            } if times else {}
        }

    return results


def analyze_false_positives(rows: list) -> dict:
    """Calculate FPR from clean run results."""
    if not rows:
        return {'fpr': 0, 'total_runs': 0, 'false_alerts': 0}
    total = len(rows)
    fp = sum(1 for r in rows if r.get('false_positive', '').lower() == 'true')
    return {
        'total_runs': total,
        'false_alerts': fp,
        'fpr': fp / total if total > 0 else 0
    }


# ══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_performance(rows: list) -> dict:
    """Calculate mean, median, stddev for each metric × mode."""
    by_mm = {}
    for row in rows:
        key = (row['metric'], row['mode'])
        if key not in by_mm:
            by_mm[key] = []
        try:
            by_mm[key].append(float(row['value_ms']))
        except (ValueError, KeyError):
            pass

    results = {}
    for (metric, mode), values in by_mm.items():
        if metric not in results:
            results[metric] = {}
        if values:
            results[metric][mode] = {
                'n': len(values),
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'stdev': statistics.stdev(values) if len(values) > 1 else 0,
                'min': min(values),
                'max': max(values),
                'values': values
            }
    return results


# ══════════════════════════════════════════════════════════════════════════════
# STATISTICAL SIGNIFICANCE (t-test: Mode B vs Mode C)
# ══════════════════════════════════════════════════════════════════════════════

def ttest_b_vs_c(perf: dict) -> dict:
    """Perform paired t-test comparing Mode B vs Mode C for each metric."""
    if not HAS_MATPLOTLIB:
        return {}
    results = {}
    for metric, modes in perf.items():
        b_vals = modes.get('mode_b', {}).get('values', [])
        c_vals = modes.get('mode_c', {}).get('values', [])
        if len(b_vals) >= 2 and len(c_vals) >= 2:
            min_len = min(len(b_vals), len(c_vals))
            t_stat, p_val = scipy_stats.ttest_rel(
                b_vals[:min_len], c_vals[:min_len]
            )
            results[metric] = {
                't_statistic': round(t_stat, 4),
                'p_value': round(p_val, 4),
                'significant': p_val < 0.05,
                'interpretation': 'significant difference' if p_val < 0.05 else 'no significant difference'
            }
    return results


# ══════════════════════════════════════════════════════════════════════════════
# CHARTS
# ══════════════════════════════════════════════════════════════════════════════

def plot_tpr_by_scenario(detection: dict):
    """Bar chart: True Positive Rate by scenario."""
    if not HAS_MATPLOTLIB:
        return

    scenarios = list(detection.keys())
    tpr_values = [detection[s]['tpr'] * 100 for s in scenarios]
    labels = [f"{s}\n({detection[s]['attack_type'][:20]})" for s in scenarios]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(labels, tpr_values, color=COLORS['mode_c'], edgecolor='black', linewidth=0.8)

    for bar, val in zip(bars, tpr_values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f'{val:.0f}%', ha='center', va='bottom', fontweight='bold')

    ax.set_ylim(0, 115)
    ax.set_ylabel('True Positive Rate (%)', fontsize=12)
    ax.set_xlabel('Attack Scenario', fontsize=12)
    ax.set_title('Detection Accuracy (TPR) by Attack Scenario\nFull Integrated Framework (Mode C)', fontsize=13)
    ax.axhline(y=100, color='grey', linestyle='--', alpha=0.5, label='Perfect detection')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(CHARTS_DIR / 'tpr_by_scenario.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {CHARTS_DIR}/tpr_by_scenario.png")


def plot_detection_latency(detection: dict):
    """Bar chart with error bars: Detection latency by scenario."""
    if not HAS_MATPLOTLIB:
        return

    scenarios = [s for s in detection if detection[s].get('detection_latency')]
    means = [detection[s]['detection_latency']['mean'] for s in scenarios]
    stdevs = [detection[s]['detection_latency']['stdev'] for s in scenarios]

    if not scenarios:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(scenarios, means, yerr=stdevs, capsize=5,
                  color=COLORS['mode_c'], edgecolor='black', alpha=0.85)

    for bar, val in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 50,
                f'{val:.0f}ms', ha='center', va='bottom', fontsize=10)

    ax.set_ylabel('Detection Latency (ms)', fontsize=12)
    ax.set_xlabel('Attack Scenario', fontsize=12)
    ax.set_title('Detection Latency by Scenario (mean ± stddev)', fontsize=13)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(CHARTS_DIR / 'detection_latency.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {CHARTS_DIR}/detection_latency.png")


def plot_performance_overhead(perf: dict):
    """Bar chart: Pipeline overhead across Mode A/B/C."""
    if not HAS_MATPLOTLIB:
        return

    key_metrics = [
        ('docker_build_baseline', 'Build Time'),
        ('cosign_sign', 'Signing'),
        ('sbom_generation', 'SBOM Gen'),
        ('admission_latency', 'Admission'),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    axes = axes.flatten()

    for idx, (metric, label) in enumerate(key_metrics):
        if metric not in perf:
            continue
        ax = axes[idx]
        modes = ['mode_a', 'mode_b', 'mode_c']
        mode_labels = ['Mode A\n(No Security)', 'Mode B\n(Build-time)', 'Mode C\n(Full)']
        values = [perf[metric].get(m, {}).get('mean', 0) for m in modes]
        colors = [COLORS[m] for m in modes]

        bars = ax.bar(mode_labels, values, color=colors, edgecolor='black', linewidth=0.7)
        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
                        f'{val:.0f}ms', ha='center', va='bottom', fontsize=9)

        ax.set_title(f'{label} (ms)', fontsize=11, fontweight='bold')
        ax.set_ylabel('Time (ms)')
        ax.grid(axis='y', alpha=0.3)

    patches = [mpatches.Patch(color=COLORS[m], label=l)
               for m, l in zip(['mode_a', 'mode_b', 'mode_c'],
                                ['No Security', 'Build-time Only', 'Full Framework'])]
    fig.legend(handles=patches, loc='lower center', ncol=3, fontsize=11, frameon=True)
    fig.suptitle('Performance Overhead — 3-Mode Comparison', fontsize=14, fontweight='bold')

    plt.tight_layout(rect=[0, 0.06, 1, 1])
    plt.savefig(CHARTS_DIR / 'performance_overhead.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {CHARTS_DIR}/performance_overhead.png")


# ══════════════════════════════════════════════════════════════════════════════
# LaTeX TABLE
# ══════════════════════════════════════════════════════════════════════════════

def generate_latex_table(detection: dict, fp: dict, perf: dict) -> str:
    latex = r"""
\begin{table}[h]
\centering
\caption{Detection Accuracy Results --- Integrated Supply Chain Security Framework}
\label{tab:detection_results}
\begin{tabular}{|l|l|c|c|c|c|}
\hline
\textbf{Scenario} & \textbf{Attack Type} & \textbf{TPR (\%)} & \textbf{FNR (\%)} & \textbf{Avg. Latency (ms)} & \textbf{Detection Layer} \\
\hline
"""
    for s, d in detection.items():
        tpr = d['tpr'] * 100
        fnr = d['fnr'] * 100
        lat = d.get('detection_latency', {}).get('mean', 0)
        layer = d['detection_layer'].replace('_', ' ').title()
        attack = d['attack_type'].replace('_', ' ').title()
        latex += f"{s} & {attack} & {tpr:.0f} & {fnr:.0f} & {lat:.0f} & {layer} \\\\\n"
        latex += r"\hline" + "\n"

    fpr_pct = fp.get('fpr', 0) * 100
    latex += f"Clean Runs (FPR) & Normal Operation & -- & -- & -- & FPR = {fpr_pct:.0f}\\% \\\\\n"
    latex += r"""\hline
\end{tabular}
\end{table}
"""
    return latex


# ══════════════════════════════════════════════════════════════════════════════
# CONSOLE REPORT
# ══════════════════════════════════════════════════════════════════════════════

def print_report(detection: dict, fp: dict, perf: dict, ttest: dict):
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║   CND Project — Results Analysis Report                              ║")
    print("╠══════════════════════════════════════════════════════════════════════╣")
    print("║  DETECTION ACCURACY                                                   ║")
    print("╠═══════════╦════════════╦═══════╦═══════╦══════════╦════════════════╣")
    print("║ Scenario  ║ Runs       ║  TPR  ║  FNR  ║ Avg(ms)  ║ Layer          ║")
    print("╠═══════════╬════════════╬═══════╬═══════╬══════════╬════════════════╣")
    for s, d in detection.items():
        tpr = d['tpr'] * 100
        fnr = d['fnr'] * 100
        lat = d.get('detection_latency', {}).get('mean', 0)
        print(f"║ {s:9s} ║ {d['total_runs']:4d}/{d['detected']:4d}   ║ {tpr:4.0f}% ║ {fnr:4.0f}% ║ {lat:7.0f}ms ║ {d['detection_layer'][:14]:14s} ║")
    print("╠══════════════════════════════════════════════════════════════════════╣")
    fpr = fp.get('fpr', 0) * 100
    print(f"║  False Positive Rate (FPR): {fpr:.0f}% ({fp.get('false_alerts',0)}/{fp.get('total_runs',0)} clean runs triggered alerts)")
    print("╠══════════════════════════════════════════════════════════════════════╣")
    print("║  PERFORMANCE OVERHEAD (Mode C vs Mode A baseline)                    ║")
    for metric, modes in perf.items():
        a = modes.get('mode_a', {}).get('mean', 0)
        c = modes.get('mode_c', {}).get('mean', 0)
        if a > 0:
            overhead = (c - a) / a * 100
            print(f"║  {metric:35s} A={a:6.0f}ms C={c:6.0f}ms Δ={overhead:+.1f}%")
    if ttest:
        print("╠══════════════════════════════════════════════════════════════════════╣")
        print("║  STATISTICAL SIGNIFICANCE (t-test: Mode B vs Mode C)                ║")
        for metric, r in ttest.items():
            sig = "✅ p<0.05" if r['significant'] else "⚪ p≥0.05"
            print(f"║  {metric:35s} t={r['t_statistic']:7.3f} p={r['p_value']:.4f} {sig}")
    print("╚══════════════════════════════════════════════════════════════════════╝")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("CND Project — Results Analysis")
    print(f"Reading from: {RESULTS_DIR}")

    det_rows = load_detection_results()
    perf_rows = load_performance_results()
    fp_rows = load_false_positive_results()

    detection = analyze_detection(det_rows) if det_rows else {}
    fp = analyze_false_positives(fp_rows)
    perf = analyze_performance(perf_rows) if perf_rows else {}
    ttest = ttest_b_vs_c(perf)

    print_report(detection, fp, perf, ttest)

    if HAS_MATPLOTLIB and detection:
        print("\nGenerating charts...")
        plot_tpr_by_scenario(detection)
        plot_detection_latency(detection)

    if HAS_MATPLOTLIB and perf:
        plot_performance_overhead(perf)

    # Save analysis JSON
    analysis = {
        'detection': detection,
        'false_positive': fp,
        'ttest': ttest,
        'summary': {
            'overall_tpr': statistics.mean([d['tpr'] for d in detection.values()]) if detection else 0,
            'overall_fpr': fp.get('fpr', 0),
        }
    }
    with open(RESULTS_DIR / 'analysis_summary.json', 'w') as f:
        json.dump(analysis, f, indent=2)

    # Generate LaTeX table
    latex = generate_latex_table(detection, fp, perf)
    with open(RESULTS_DIR / 'table_detection.tex', 'w') as f:
        f.write(latex)
    print(f"\n  LaTeX table saved: {RESULTS_DIR}/table_detection.tex")
    print(f"  Analysis JSON saved: {RESULTS_DIR}/analysis_summary.json")
    print(f"  Charts saved in: {CHARTS_DIR}/")


if __name__ == '__main__':
    main()
