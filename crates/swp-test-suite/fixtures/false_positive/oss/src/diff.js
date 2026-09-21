'use strict';

// A keyed list diff. It is here because half the front-end code in the world
// contains some version of these forty lines, and because its statement shapes
// repeat within the file: `if (a === b)`, `i++`, `return out`. Those are the
// spans a content address cannot tell apart.

function same(left, right) {
  if (left === right) {
    return true;
  }
  if (left === null || right === null) {
    return false;
  }
  if (typeof left !== 'object' || typeof right !== 'object') {
    return false;
  }
  const a = Object.keys(left);
  const b = Object.keys(right);
  if (a.length !== b.length) {
    return false;
  }
  for (const key of a) {
    if (!same(left[key], right[key])) {
      return false;
    }
  }
  return true;
}

function indexByKey(rows) {
  const map = new Map();
  for (let i = 0; i < rows.length; i++) {
    map.set(rows[i].key, i);
  }
  return map;
}

function diff(before, after) {
  const patches = [];
  const seen = indexByKey(after);
  const keep = indexByKey(before);
  for (const row of before) {
    if (!seen.has(row.key)) {
      patches.push({ op: 'remove', key: row.key });
    }
  }
  for (let i = 0; i < after.length; i++) {
    const row = after[i];
    if (!keep.has(row.key)) {
      patches.push({ op: 'insert', at: i, row });
      continue;
    }
    const previous = before[keep.get(row.key)];
    if (!same(previous, row)) {
      patches.push({ op: 'update', at: i, row });
    }
  }
  return patches;
}

function apply(rows, patches) {
  const out = rows.slice();
  for (const patch of patches) {
    if (patch.op === 'remove') {
      const at = out.findIndex((row) => row.key === patch.key);
      if (at >= 0) {
        out.splice(at, 1);
      }
    } else if (patch.op === 'insert') {
      out.splice(patch.at, 0, patch.row);
    } else if (patch.op === 'update') {
      out[patch.at] = patch.row;
    }
  }
  return out;
}

function reconcile(before, after) {
  const patches = diff(before, after);
  if (patches.length > before.length * 0.6) {
    return { op: 'replace', rows: after };
  }
  return { op: 'patch', patches };
}

module.exports = { same, indexByKey, diff, apply, reconcile };
