"use strict";

const { rgbToHex, luminance, contrastRatio, toPercentage } = require("./color");

const SWATCHES = [
  [255, 255, 255],
  [17, 17, 17],
  [0, 123, 255],
  [220, 53, 69],
  [40, 167, 69],
];

const READABILITY_TARGET = 4.5;

function describe(swatch) {
  const [red, green, blue] = swatch;
  const lightness = luminance(red, green, blue);
  const ratio = contrastRatio(lightness, 1000 - lightness);
  return {
    hex: rgbToHex(red, green, blue),
    ratio: Math.round(ratio * 100) / 100,
    passes: ratio >= READABILITY_TARGET,
  };
}

function coverage(results) {
  const good = results.filter((r) => r.passes).length;
  if (results.length === 0) {
    return 0;
  }
  return toPercentage(good / results.length);
}

function main() {
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

module.exports = { describe, coverage, main, SWATCHES, READABILITY_TARGET };
