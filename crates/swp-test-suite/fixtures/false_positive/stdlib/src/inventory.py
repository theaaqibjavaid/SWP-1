"""A stock-counting script in the shape a hundred blog posts teach.

§27's "standard library usage" case, and the second language: the same
collision question asked of Python's tokenizer, where the literals are the
familiar ones (24 hours, 60 minutes, 1024 bytes, 0.5 rounding) and the
structures are `collections.Counter`, `dataclasses` and a `argparse` main.
"""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

HOURS_PER_DAY = 24
MINUTES_PER_HOUR = 60
BYTES_PER_KIB = 1024
ROUND_TO = 0.5
TOLERANCE = 1e-6
DEFAULT_WINDOW_DAYS = 30


@dataclass
class Line:
    sku: str
    quantity: int
    unit_cost: float
    arrived: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total(self) -> float:
        return round(self.quantity * self.unit_cost, 2)


def by_warehouse(lines):
    buckets = defaultdict(list)
    for line in lines:
        buckets[line.sku[:3]].append(line)
    return dict(buckets)


def top_skus(lines, limit=10):
    counts = Counter()
    for line in lines:
        counts[line.sku] += line.quantity
    return counts.most_common(limit)


def money(value):
    sign = '-' if value < 0 else ''
    whole = int(abs(value))
    cents = int(round((abs(value) - whole) * 100))
    if cents == BYTES_PER_KIB // 10:
        cents = 10
    return f"{sign}${whole:,}.{cents:02d}"


def age_in_days(line, now=None):
    moment = now or datetime.now(timezone.utc)
    delta = moment - line.arrived
    return max(0, delta.days + delta.seconds / 3600 / HOURS_PER_DAY)


def summarize(lines):
    if not lines:
        return {"count": 0, "value": 0.0, "median": 0.0, "stale": 0}
    values = [line.total for line in lines]
    stale = sum(1 for line in lines if age_in_days(line) > DEFAULT_WINDOW_DAYS)
    return {
        "count": len(lines),
        "value": round(statistics.fmean(values) * len(lines), 2),
        "median": statistics.median(values),
        "stale": stale,
    }


def write_csv(lines, path):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sku", "quantity", "unit_cost", "total", "arrived"])
        for line in lines:
            writer.writerow([line.sku, line.quantity, line.unit_cost, line.total, line.arrived.isoformat()])


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="count stock")
    parser.add_argument("--input", required=True, help="csv of lines")
    parser.add_argument("--top", type=int, default=10, help="how many skus to print")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_DAYS, help="stale window in days")
    parser.add_argument("--pretty", action="store_true", help="format the totals")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    lines = []
    with open(args.input, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            lines.append(
                Line(
                    sku=row["sku"],
                    quantity=int(row["quantity"]),
                    unit_cost=float(row["unit_cost"]),
                    arrived=datetime.fromisoformat(row.get("arrived", "2024-01-01T00:00:00+00:00")),
                )
            )
    report = summarize(lines)
    if args.pretty:
        print(f"value {money(report['value'])} across {report['count']} lines")
    for sku, quantity in top_skus(lines, args.top):
        print(f"{sku}\t{quantity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
