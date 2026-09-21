import json

from color import contrast_ratio, luminance, rgb_to_hex, to_percentage

SWATCHES = [
    (255, 255, 255),
    (17, 17, 17),
    (0, 123, 255),
    (220, 53, 69),
    (40, 167, 69),
]

READABILITY_TARGET = 4.5


def describe(swatch):
    red, green, blue = swatch
    lightness = luminance(red, green, blue)
    ratio = contrast_ratio(lightness, 1000 - lightness)
    return {
        "hex": rgb_to_hex(red, green, blue),
        "ratio": round(ratio * 100) / 100,
        "passes": ratio >= READABILITY_TARGET,
    }


def coverage(rows):
    good = len([row for row in rows if row["passes"]])
    if len(rows) == 0:
        return 0
    return to_percentage(good / len(rows))


def main():
    rows = [describe(swatch) for swatch in SWATCHES]
    return {"rows": rows, "coverage": coverage(rows), "target": READABILITY_TARGET}


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
