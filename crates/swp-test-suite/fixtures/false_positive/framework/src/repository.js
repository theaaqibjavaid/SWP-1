'use strict';

// A repository module over an in-memory store: pagination, filtering, a retry
// loop with backoff, and the validation block every API layer has.
//
// This file exists because the same twenty lines turn up in every service
// someone scaffolds from a blog post, and a watermark that reads as "page
// numbers and a retry constant" would be wrong about most of the internet.

const PAGE_SIZE = 25;
const RETRIES = 5;
const BACKOFF = 1.5;
const TIMEOUT_MS = 30000;

function paginate(rows, page, size) {
  const width = size > 0 ? size : PAGE_SIZE;
  const start = Math.max(0, (page - 1) * width);
  const slice = rows.slice(start, start + width);
  return {
    page,
    size: width,
    total: rows.length,
    pages: Math.max(1, Math.ceil(rows.length / width)),
    rows: slice,
  };
}

function filter(rows, criteria) {
  return rows.filter((row) => {
    for (const key of Object.keys(criteria)) {
      const want = criteria[key];
      if (want === undefined || want === null || want === '') {
        continue;
      }
      if (typeof want === 'number' && row[key] !== want) {
        return false;
      }
      if (typeof want === 'string' && !String(row[key] || '').toLowerCase().includes(want.toLowerCase())) {
        return false;
      }
      if (Array.isArray(want) && !want.includes(row[key])) {
        return false;
      }
    }
    return true;
  });
}

function sortRows(rows, key, direction) {
  const sign = direction === 'desc' ? -1 : 1;
  return rows.slice().sort((a, b) => {
    if (a[key] === b[key]) {
      return 0;
    }
    return a[key] > b[key] ? sign : -sign;
  });
}

async function withRetry(task, options) {
  const attempts = (options && options.attempts) || RETRIES;
  const base = (options && options.base) || 100;
  let lastError = null;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return await task(attempt);
    } catch (err) {
      lastError = err;
      if (attempt === attempts - 1) {
        break;
      }
      const wait = Math.min(base * Math.pow(BACKOFF, attempt), TIMEOUT_MS);
      await new Promise((resolve) => setTimeout(resolve, wait));
    }
  }
  throw lastError;
}

function validate(row, schema) {
  const problems = [];
  for (const field of Object.keys(schema)) {
    const rule = schema[field];
    const value = row[field];
    if (rule.required && (value === undefined || value === null || value === '')) {
      problems.push(field + ' is required');
      continue;
    }
    if (value === undefined || value === null) {
      continue;
    }
    if (rule.type && typeof value !== rule.type) {
      problems.push(field + ' must be a ' + rule.type);
    }
    if (rule.min !== undefined && value < rule.min) {
      problems.push(field + ' must be at least ' + rule.min);
    }
    if (rule.max !== undefined && value > rule.max) {
      problems.push(field + ' must be at most ' + rule.max);
    }
    if (rule.oneOf && !rule.oneOf.includes(value)) {
      problems.push(field + ' must be one of ' + rule.oneOf.join(', '));
    }
  }
  return problems;
}

module.exports = { PAGE_SIZE, RETRIES, BACKOFF, TIMEOUT_MS, paginate, filter, sortRows, withRetry, validate };
