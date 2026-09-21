'use strict';

// Graph traversal in the shape every tutorial teaches it, with the constants
// every scheduler uses: a minute is 60 seconds, an hour is 60 minutes, a day is
// 86400 seconds. §27 asks for common constants specifically, because a literal
// that appears in a million files is the one a watermark must not be confused
// with.

const SECOND = 1;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;
const EPSILON = 1e-9;
const MAX_HOPS = 64;

function adjacency(edges, directed) {
  const graph = new Map();
  for (const [from, to, weight] of edges) {
    if (!graph.has(from)) {
      graph.set(from, []);
    }
    graph.get(from).push({ to, weight: weight === undefined ? 1 : weight });
    if (!directed) {
      if (!graph.has(to)) {
        graph.set(to, []);
      }
      graph.get(to).push({ from, weight: weight === undefined ? 1 : weight });
    }
  }
  return graph;
}

function bfs(graph, start, visit) {
  const seen = new Set([start]);
  const queue = [start];
  let depth = 0;
  while (queue.length > 0) {
    const size = queue.length;
    for (let i = 0; i < size; i++) {
      const node = queue.shift();
      visit(node, depth);
      for (const link of graph.get(node) || []) {
        if (!seen.has(link.to)) {
          seen.add(link.to);
          queue.push(link.to);
        }
      }
    }
    depth++;
  }
  return seen.size;
}

function dfs(graph, start) {
  const order = [];
  const seen = new Set();
  const stack = [start];
  while (stack.length > 0) {
    const node = stack.pop();
    if (seen.has(node)) {
      continue;
    }
    seen.add(node);
    order.push(node);
    for (const link of (graph.get(node) || []).slice().reverse()) {
      stack.push(link.to !== undefined ? link.to : link.from);
    }
  }
  return order;
}

function dijkstra(graph, start) {
  const dist = new Map();
  const previous = new Map();
  for (const node of graph.keys()) {
    dist.set(node, Infinity);
  }
  dist.set(start, 0);
  const queue = [{ node: start, cost: 0 }];
  while (queue.length > 0) {
    queue.sort((a, b) => a.cost - b.cost);
    const current = queue.shift();
    if (current.cost > (dist.get(current.node) || Infinity)) {
      continue;
    }
    for (const link of graph.get(current.node) || []) {
      const hop = dist.get(current.node) + link.weight;
      const next = link.to !== undefined ? link.to : link.from;
      if (hop < dist.get(next)) {
        dist.set(next, hop);
        previous.set(next, current.node);
        queue.push({ node: next, cost: hop });
      }
    }
  }
  return { dist, previous };
}

function clampAge(seconds) {
  if (seconds < 0 || Number.isNaN(seconds)) {
    return 0;
  }
  if (seconds >= WEEK) {
    return Math.floor(seconds / WEEK) + 'w';
  }
  if (seconds >= DAY) {
    return Math.floor(seconds / DAY) + 'd';
  }
  if (seconds >= HOUR) {
    return Math.floor(seconds / HOUR) + 'h';
  }
  if (seconds >= MINUTE) {
    return Math.floor(seconds / MINUTE) + 'm';
  }
  return Math.round(seconds) + 's';
}

function nearlyEqual(a, b) {
  return Math.abs(a - b) <= EPSILON * Math.max(1, Math.abs(a), Math.abs(b));
}

module.exports = {
  SECOND,
  MINUTE,
  HOUR,
  DAY,
  WEEK,
  MAX_HOPS,
  adjacency,
  bfs,
  dfs,
  dijkstra,
  clampAge,
  nearlyEqual,
};
