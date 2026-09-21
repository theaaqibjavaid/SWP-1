import { contrastRatio, luminance, rgbToHex, toPercentage } from "./color";

interface Swatch {
  red: number;
  green: number;
  blue: number;
}

const SWATCHES: Swatch[] = [
  { red: 255, green: 255, blue: 255 },
  { red: 17, green: 17, blue: 17 },
  { red: 0, green: 123, blue: 255 },
  { red: 220, green: 53, blue: 69 },
  { red: 40, green: 167, blue: 69 },
];

const READABILITY_TARGET = 4.5;

function describe(swatch: Swatch): { hex: string; ratio: number; passes: boolean } {
  const lightness = luminance(swatch.red, swatch.green, swatch.blue);
  const ratio = contrastRatio(lightness, 1000 - lightness);
  return {
    hex: rgbToHex(swatch.red, swatch.green, swatch.blue),
    ratio: Math.round(ratio * 100) / 100,
    passes: ratio >= READABILITY_TARGET,
  };
}

function coverage(rows: Array<{ passes: boolean }>): number {
  const good = rows.filter((r) => r.passes).length;
  if (rows.length === 0) {
    return 0;
  }
  return toPercentage(good / rows.length);
}

export function main(): { rows: ReturnType<typeof describe>[]; coverage: number; target: number } {
  const rows = SWATCHES.map(describe);
  return {
    rows,
    coverage: coverage(rows),
    target: READABILITY_TARGET,
  };
}

if (require.main === module) {
  process.stdout.write(JSON.stringify(main(), null, 2) + "\n");
}
