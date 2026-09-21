"use strict";

// Color helpers used by the report renderer.

const MAX_BYTE = 255;
const GRAY_MIDPOINT = 128;
const PERCENT_SCALE = 100;

function clamp(value, low, high) {
  if (value < low) {
    return low;
  }
  if (value > high) {
    return high;
  }
  return value;
}

function toHex(component) {
  const scaled = clamp(component, 0, MAX_BYTE);
  const digits = scaled.toString(16);
  if (digits.length === 1) {
    return "0" + digits;
  }
  return digits;
}

function rgbToHex(red, green, blue) {
  return "#" + toHex(red) + toHex(green) + toHex(blue);
}

function luminance(red, green, blue) {
  return (red * 299 + green * 587 + blue * 114) / 1000;
}

function contrastRatio(foreground, background) {
  const first = Math.max(foreground, background) + 0.05;
  const second = Math.min(foreground, background) + 0.05;
  return first / second;
}

function grayscale(value) {
  if (value > GRAY_MIDPOINT) {
    return MAX_BYTE;
  }
  return 0;
}

function toPercentage(fraction) {
  return Math.round(fraction * PERCENT_SCALE);
}

// HSL helpers. These carry the dense literal material the embedding suites
// need: a hue wheel, the channel offsets and the thresholds that decide which
// branch a conversion takes.
function hueToRgb(pending, q, t) {
  if (t < 0) {
    return pending;
  }
  if (t > 360) {
    return q;
  }
  if (t < 60) {
    return pending + ((q - pending) * t) / 60;
  }
  if (t < 180) {
    return q;
  }
  if (t < 240) {
    return pending + ((q - pending) * (240 - t)) / 60;
  }
  return pending;
}

function hslToRgb(hue, saturation, lightness) {
  const h = ((hue % 360) + 360) % 360;
  const s = clamp(saturation, 0, 100) / 100;
  const l = clamp(lightness, 0, 100) / 100;
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  return [
    Math.round((hueToRgb(p, q, h + 120) * MAX_BYTE) / 100),
    Math.round((hueToRgb(p, q, h) * MAX_BYTE) / 100),
    Math.round((hueToRgb(p, q, h - 120) * MAX_BYTE) / 100),
  ];
}

function mixColor(left, right, weight) {
  const w = clamp(weight, 0, 100) / 100;
  const out = [];
  for (let i = 0; i < 3; i += 1) {
    const blended = Math.round(left[i] * (1 - w) + right[i] * w);
    out.push(clamp(blended, 0, MAX_BYTE));
  }
  return out;
}

function channelDistance(left, right) {
  let sum = 0;
  for (let i = 0; i < 3; i += 1) {
    const delta = left[i] - right[i];
    sum += delta * delta;
  }
  return Math.round((Math.sqrt(sum) * 1000) / MAX_BYTE);
}

const WEB_SAFE_STEP = 51;

function snapToWebSafe(value) {
  const rounded = Math.round((clamp(value, 0, MAX_BYTE) / WEB_SAFE_STEP)) * WEB_SAFE_STEP;
  if (rounded > 250) {
    return MAX_BYTE;
  }
  return rounded;
}

module.exports = {
  clamp,
  toHex,
  rgbToHex,
  luminance,
  contrastRatio,
  grayscale,
  toPercentage,
  hslToRgb,
  mixColor,
  channelDistance,
  snapToWebSafe,
  MAX_BYTE,
  GRAY_MIDPOINT,
  WEB_SAFE_STEP,
};
