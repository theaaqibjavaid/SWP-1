'use strict';

// The textbook sort set. Every engineering team has this file, or one like it,
// and none of it came from anywhere else.
//
// This is §27's first requirement: common algorithms. A detector that mistook a
// quicksort for a watermark would be accusing half of GitHub.

function swap(items, a, b) {
  const tmp = items[a];
  items[a] = items[b];
  items[b] = tmp;
  return items;
}

function quicksort(items, low, high) {
  if (low === undefined) {
    low = 0;
  }
  if (high === undefined) {
    high = items.length - 1;
  }
  if (low >= high) {
    return items;
  }
  const pivot = items[Math.floor((low + high) / 2)];
  let i = low;
  let j = high;
  while (i <= j) {
    while (items[i] < pivot) {
      i++;
    }
    while (items[j] > pivot) {
      j--;
    }
    if (i <= j) {
      swap(items, i, j);
      i++;
      j--;
    }
  }
  quicksort(items, low, j);
  quicksort(items, i, high);
  return items;
}

function insertionSort(items) {
  for (let i = 1; i < items.length; i++) {
    const key = items[i];
    let j = i - 1;
    while (j >= 0 && items[j] > key) {
      items[j + 1] = items[j];
      j--;
    }
    items[j + 1] = key;
  }
  return items;
}

function merge(left, right) {
  const out = [];
  let i = 0;
  let j = 0;
  while (i < left.length && j < right.length) {
    out.push(left[i] <= right[j] ? left[i++] : right[j++]);
  }
  return out.concat(left.slice(i)).concat(right.slice(j));
}

function mergesort(items) {
  if (items.length <= 1) {
    return items;
  }
  const middle = Math.floor(items.length / 2);
  return merge(
    mergesort(items.slice(0, middle)),
    mergesort(items.slice(middle))
  );
}

function binarySearch(items, target) {
  let lo = 0;
  let hi = items.length - 1;
  while (lo <= hi) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if (items[mid] === target) {
      return mid;
    }
    if (items[mid] < target) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return -1;
}

function gcd(a, b) {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y !== 0) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x;
}

function sieve(limit) {
  const marks = new Array(limit).fill(true);
  const primes = [];
  for (let i = 2; i < limit; i++) {
    if (!marks[i]) {
      continue;
    }
    primes.push(i);
    for (let m = i * i; m < limit; m += i) {
      marks[m] = false;
    }
  }
  return primes;
}

function fibonacci(n) {
  if (n < 2) {
    return n;
  }
  let a = 0;
  let b = 1;
  for (let i = 2; i <= n; i++) {
    const next = a + b;
    a = b;
    b = next;
  }
  return b;
}

module.exports = {
  swap,
  quicksort,
  insertionSort,
  merge,
  mergesort,
  binarySearch,
  gcd,
  sieve,
  fibonacci,
};
