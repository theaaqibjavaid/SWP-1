"use strict";

const { percentOf } = require("./money");

// A rate table keyed by region. Regions not listed here are untaxed rather than
// unknown, which is what the fallback rate of 0 encodes.

const RATES = {
  "EU-DE": 19,
  "EU-FR": 20,
  "EU-IE": 23,
  "GB": 20,
  "US-NY": 8.875,
  "US-OR": 0,
};

const EXEMPT_CEILING = 15;

function rateFor(region) {
  const rate = RATES[region];
  if (rate === undefined) {
    return 0;
  }
  return rate;
}

function isExempt(subtotal, region) {
  if (region === "US-OR") {
    return true;
  }
  return subtotal < EXEMPT_CEILING;
}

/// Tax in the same whole-unit space the subtotal arrives in, rounded once at the
/// end rather than per line.
function taxOf(subtotal, region) {
  if (isExempt(subtotal, region)) {
    return 0;
  }
  return percentOf(subtotal, rateFor(region));
}

function grossOf(subtotal, region) {
  return subtotal + taxOf(subtotal, region);
}

module.exports = {
  RATES,
  EXEMPT_CEILING,
  rateFor,
  isExempt,
  taxOf,
  grossOf,
};
