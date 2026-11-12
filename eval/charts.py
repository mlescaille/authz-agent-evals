"""Publication charts for the headline metrics. No network, no extra fonts."""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

COLORS = {"A": "#3B6D9A", "B": "#E07A3D", "C": "#2F7D4A"}
CONDITION_LABELS = {
    "A": "A  code only",
    "B": "B  code + description",
    "C": "C  code + scoped token",
}
CLASS_LABELS = {
    "relationship": "Relationship",
    "control": "IDOR control",
    "all": "All bugs",
}


def _style(ax, title):
    ax.set_title(title, loc="left", fontsize=13, pad=14)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(labelsize=9)


def _subtitle(fig, text):
    fig.text(0.01, 0.01, text, fontsize=8, color="#444444")


def write_detection(metrics, path):
    fig, ax = plt.subplots(figsize=(8.4, 4.8))
    classes = ["relationship", "control", "all"]
    conditions = ["A", "B", "C"]
    x = np.arange(len(classes))
    width = 0.24
    for offset, condition in enumerate(conditions):
        means = []
        for class_name in classes:
            block = metrics["conditions"][condition]["recall"][class_name]
            means.append(0 if block["mean"] is None else block["mean"])
        positions = x + (offset - 1) * width
        ax.bar(
            positions,
            [value * 100 for value in means],
            width=width,
            color=COLORS[condition],
            label=CONDITION_LABELS[condition],
        )
        for class_index, class_name in enumerate(classes):
            values = metrics["conditions"][condition]["recall"][class_name]["values"]
            for dot_index, value in enumerate(values):
                jitter = (dot_index - (len(values) - 1) / 2) * 0.03
                ax.plot(
                    positions[class_index] + jitter,
                    value * 100,
                    "o",
                    color="#1a1a1a",
                    markersize=4,
                    zorder=3,
                )
    ax.set_ylabel("Detection rate (%)")
    ax.set_xticks(x, [CLASS_LABELS[name] for name in classes])
    ax.set_ylim(0, 100)
    ax.legend(frameon=False, fontsize=8)
    _style(ax, "Detection rate by bug class")
    _subtitle(fig, "Mean of 5 runs. Dots are individual runs. Small n.")
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(path, dpi=160)
    plt.close(fig)


def write_frequency(metrics, path):
    bugs = metrics["per_bug"]
    conditions = ["A", "B", "C"]
    matrix = np.array(
        [[bug["counts"][condition]["caught"] for condition in conditions] for bug in bugs],
        dtype=float,
    )
    fig, ax = plt.subplots(figsize=(7.2, 6.2))
    image = ax.imshow(matrix, cmap="Blues", vmin=0, vmax=5, aspect="auto")
    ax.set_xticks(range(3), [CONDITION_LABELS[condition] for condition in conditions], fontsize=8)
    ax.set_yticks(
        range(len(bugs)),
        [f"{bug['id']}  {bug['title']}" for bug in bugs],
        fontsize=8,
    )
    for row in range(matrix.shape[0]):
        for col in range(matrix.shape[1]):
            value = int(matrix[row, col])
            ax.text(
                col,
                row,
                f"{value}/5",
                ha="center",
                va="center",
                color="white" if value >= 3 else "#1a1a1a",
                fontsize=8,
            )
    boundary = sum(1 for bug in bugs if bug["class"] == "relationship") - 0.5
    ax.axhline(boundary, color="#666666", linewidth=0.6)
    colorbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    colorbar.set_label("Runs detected (of 5)", fontsize=8)
    _style(ax, "How often each bug was detected")
    _subtitle(fig, "Caught counts across 5 runs. Relationship bugs above the line, IDOR controls below. Small n.")
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(path, dpi=160)
    plt.close(fig)


def write_false_positives(metrics, path):
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    conditions = ["A", "B", "C"]
    x = np.arange(len(conditions))
    means = []
    dots = []
    for index, condition in enumerate(conditions):
        value = metrics["conditions"][condition]["false_positive_rate"]["mean"]
        means.append(0 if value is None else value * 100)
        block = metrics["conditions"][condition]["false_positive_rate"]["values"]
        for dot_index, rate in enumerate(block):
            jitter = (dot_index - (len(block) - 1) / 2) * 0.04
            dots.append((index + jitter, rate * 100))
    ax.bar(x, means, color=[COLORS[condition] for condition in conditions], width=0.62)
    for xpos, ypos in dots:
        ax.plot(xpos, ypos, "o", color="#1a1a1a", markersize=5, zorder=3)
    ax.set_xticks(x, [CONDITION_LABELS[condition] for condition in conditions])
    ax.set_ylabel("False-positive rate (%)")
    ax.set_ylim(0, 100)
    _style(ax, "Findings the verifier could not confirm")
    _subtitle(fig, "False positives / confirmed findings, per run (dots) and the mean (bars). Runs with no confirmed findings are omitted. Small n.")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=160)
    plt.close(fig)


def write_authority(metrics, path):
    rows = [row for row in metrics["per_run"] if row["condition"] == "C"]
    rows = sorted(rows, key=lambda row: row["run"])
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    labels = [f"C{row['run']}" for row in rows]
    blocked = [row.get("authority", {}).get("out_of_scope_blocked", 0) for row in rows]
    allowed = [row.get("authority", {}).get("out_of_scope_allowed", 0) for row in rows]
    x = np.arange(len(rows))
    ax.bar(x, blocked, color="#3B6D9A", label="Blocked")
    ax.bar(x, allowed, bottom=blocked, color="#B33C3C", label="Allowed")
    ax.set_xticks(x, labels)
    ax.set_ylabel("Out-of-scope requests")
    ax.legend(frameon=False, fontsize=8)
    _style(ax, "Scoped credential: requests outside the grant")
    _subtitle(fig, "Condition C only. Blocked requests were refused by the harness. Allowed requests were forwarded. Small n.")
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(path, dpi=160)
    plt.close(fig)


def write_charts(metrics, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    write_detection(metrics, directory / "detection_rate.png")
    write_frequency(metrics, directory / "catch_frequency.png")
    write_false_positives(metrics, directory / "false_positive_rate.png")
    write_authority(metrics, directory / "scoped_authority.png")
