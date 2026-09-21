export const MAX_BYTE = 255;
export const GRAY_MIDPOINT = 128;

export function clamp(value: number, low: number, high: number): number {
  if (value < low) {
    return low;
  }
  if (value > high) {
    return high;
  }
  return value;
}

function toHex(component: number): string {
  const scaled = clamp(component, 0, MAX_BYTE);
  const digits = scaled.toString(16);
  if (digits.length === 1) {
    return "0" + digits;
  }
  return digits;
}

export function rgbToHex(red: number, green: number, blue: number): string {
  return "#" + toHex(red) + toHex(green) + toHex(blue);
}

export function luminance(red: number, green: number, blue: number): number {
  return (red * 299 + green * 587 + blue * 114) / 1000;
}

export function contrastRatio(foreground: number, background: number): number {
  const first = Math.max(foreground, background) + 0.05;
  const second = Math.min(foreground, background) + 0.05;
  return first / second;
}

export function grayscale(value: number): number {
  if (value > GRAY_MIDPOINT) {
    return MAX_BYTE;
  }
  return 0;
}

const PERCENT_SCALE = 100;
const WEB_SAFE_STEP = 51;

export function toPercentage(fraction: number): number {
  return Math.round(fraction * PERCENT_SCALE);
}

function hueToRgb(pending: number, q: number, t: number): number {
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

export function hslToRgb(hue: number, saturation: number, lightness: number): number[] {
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

export function mixColor(left: number[], right: number[], weight: number): number[] {
  const w = clamp(weight, 0, 100) / 100;
  const out: number[] = [];
  for (let i = 0; i < 3; i += 1) {
    const blended = Math.round(left[i] * (1 - w) + right[i] * w);
    out.push(clamp(blended, 0, MAX_BYTE));
  }
  return out;
}

export function channelDistance(left: number[], right: number[]): number {
  let sum = 0;
  for (let i = 0; i < 3; i += 1) {
    const delta = left[i] - right[i];
    sum += delta * delta;
  }
  return Math.round((Math.sqrt(sum) * 1000) / MAX_BYTE);
}

export function snapToWebSafe(value: number): number {
  const rounded = Math.round(clamp(value, 0, MAX_BYTE) / WEB_SAFE_STEP) * WEB_SAFE_STEP;
  if (rounded > 250) {
    return MAX_BYTE;
  }
  return rounded;
}
