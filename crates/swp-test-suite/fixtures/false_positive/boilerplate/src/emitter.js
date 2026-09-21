'use strict';

// An event emitter, a deferred, a debounce and a throttle: the four helpers
// every browser-era codebase either imports or re-implements from memory.
//
// §27's "common boilerplate". Nothing here is novel, which is the point: a
// detector that keys on `listeners.get(type) || []` would confirm on any tree
// that has an event emitter in it, and there are millions.

class Emitter {
  constructor() {
    this.listeners = new Map();
    this.once = new Map();
  }
  on(type, handler) {
    const list = this.listeners.get(type) || [];
    list.push(handler);
    this.listeners.set(type, list);
    return () => this.off(type, handler);
  }
  off(type, handler) {
    const list = this.listeners.get(type) || [];
    const at = list.indexOf(handler);
    if (at >= 0) {
      list.splice(at, 1);
    }
    this.listeners.set(type, list);
  }
  emit(type, payload) {
    for (const handler of (this.listeners.get(type) || []).slice()) {
      handler(payload);
    }
    const single = this.once.get(type) || [];
    this.once.set(type, []);
    for (const handler of single) {
      handler(payload);
    }
    return this;
  }
}

function deferred() {
  let resolve = null;
  let reject = null;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function debounce(fn, wait) {
  let timer = null;
  const delay = wait === undefined ? 150 : wait;
  return function debounced(...args) {
    if (timer) {
      clearTimeout(timer);
    }
    timer = setTimeout(() => {
      timer = null;
      fn.apply(this, args);
    }, delay);
  };
}

function throttle(fn, every) {
  const gap = every === undefined ? 100 : every;
  let last = 0;
  let pending = null;
  return function throttled(...args) {
    const now = Date.now();
    const left = gap - (now - last);
    if (left <= 0) {
      last = now;
      return fn.apply(this, args);
    }
    if (!pending) {
      pending = setTimeout(() => {
        last = Date.now();
        pending = null;
        fn.apply(this, args);
      }, left);
    }
    return undefined;
  };
}

function deepClone(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(deepClone);
  }
  if (value instanceof Date) {
    return new Date(value.getTime());
  }
  if (value instanceof Map) {
    return new Map([...value.entries()].map(([k, v]) => [deepClone(k), deepClone(v)]));
  }
  if (value instanceof Set) {
    return new Set([...value.values()].map(deepClone));
  }
  const out = {};
  for (const key of Object.keys(value)) {
    out[key] = deepClone(value[key]);
  }
  return out;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms || 0));
}

module.exports = { Emitter, deferred, debounce, throttle, deepClone, sleep };
