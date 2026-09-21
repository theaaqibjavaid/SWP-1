'use strict';

// Colour, date and string utilities: the three files every front-end repo has,
// written the same way because there is only one way to write them.
//
// The constants are the ones §27 names — 255, 360, 12, 60, 1000, 1024 — and the
// structures are the popular ones, so this is the corpus most likely to collide
// with a real watermark by content alone.

const RGB_MAX = 255;
const HUE_MAX = 360;
const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

function clamp(value, low, high) {
  if (value < low) {
    return low;
  }
  if (value > high) {
    return high;
  }
  return value;
}

function hex(n) {
  const v = clamp(Math.round(n), 0, RGB_MAX);
  return v.toString(16).padStart(2, '0');
}

function rgbToHex(r, g, b) {
  return '#' + hex(r) + hex(g) + hex(b);
}

function hexToRgb(text) {
  const body = String(text).replace('#', '');
  if (body.length !== 6) {
    throw new Error('expected six hexadecimal digits: ' + text);
  }
  return {
    r: parseInt(body.slice(0, 2), 16),
    g: parseInt(body.slice(2, 4), 16),
    b: parseInt(body.slice(4, 6), 16),
  };
}

function luminance(color) {
  const { r, g, b } = color;
  return (0.2126 * r + 0.7152 * g + 0.0722 * b) / RGB_MAX;
}

function contrast(a, b) {
  const first = luminance(a) + 0.05;
  const second = luminance(b) + 0.05;
  return first > second ? first / second : second / first;
}

function hslToRgb(h, s, l) {
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;
  let rgb;
  if (h < 60) {
    rgb = [c, x, 0];
  } else if (h < 120) {
    rgb = [x, c, 0];
  } else if (h < 180) {
    rgb = [0, c, x];
  } else if (h < 240) {
    rgb = [0, x, c];
  } else if (h < 300) {
    rgb = [x, 0, c];
  } else {
    rgb = [c, 0, x];
  }
  return {
    r: Math.round((rgb[0] + m) * RGB_MAX),
    g: Math.round((rgb[1] + m) * RGB_MAX),
    b: Math.round((rgb[2] + m) * RGB_MAX),
  };
}

function bytes(count) {
  if (count >= GB) {
    return (count / GB).toFixed(2) + ' GB';
  }
  if (count >= MB) {
    return (count / MB).toFixed(2) + ' MB';
  }
  if (count >= KB) {
    return (count / KB).toFixed(1) + ' KB';
  }
  return count + ' B';
}

function plural(count, word) {
  return count + ' ' + word + (count === 1 ? '' : 's');
}

function truncate(text, max) {
  const width = max === undefined ? 80 : max;
  if (text.length <= width) {
    return text;
  }
  return text.slice(0, width - 1).trimEnd() + '…';
}

function slugify(text) {
  return String(text)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function titleCase(text) {
  return String(text).replace(/\b\w/g, (c) => c.toUpperCase());
}

function percent(part, whole) {
  if (!whole) {
    return 0;
  }
  return Math.round((part / whole) * 10000) / 100;
}

module.exports = {
  RGB_MAX,
  HUE_MAX,
  KB,
  MB,
  GB,
  clamp,
  hex,
  rgbToHex,
  hexToRgb,
  luminance,
  contrast,
  hslToRgb,
  bytes,
  plural,
  truncate,
  slugify,
  titleCase,
  percent,
};
