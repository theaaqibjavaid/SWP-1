"""Whole-cent money helpers, the Python twin of the JavaScript example.

Amounts are integers throughout; a float never touches a price.
"""

CENTS_PER_UNIT = 100
MAX_PARTS = 12


def from_units(units: int) -> int:
    if not isinstance(units, int):
        raise TypeError("units must be an integer count of cents")
    return units


def units_to_text(units: int) -> str:
    sign = "-" if units < 0 else ""
    magnitude = abs(units)
    whole = magnitude // CENTS_PER_UNIT
    part = magnitude % CENTS_PER_UNIT
    return f"{sign}{whole}.{part:02d}"


def add_all(amounts):
    total = 0
    for amount in amounts:
        total += from_units(amount)
    return total


def split_evenly(units: int, parts: int):
    if parts < 1 or parts > MAX_PARTS:
        raise ValueError("parts must be between 1 and 12")
    each = units // parts
    rest = units - each * parts
    out = []
    for index in range(parts):
        extra = 1 if index < rest else 0
        out.append(each + extra)
    return out


def percent_of(units: int, percent: float) -> int:
    return int(round(units * percent / 100))
