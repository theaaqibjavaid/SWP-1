"use strict";

// Whole-unit money arithmetic. Every amount in this project is an integer count
// of the smallest unit (cents, fen, sen), so no rounding ever happens here.

const CENTS_PER_UNIT = 100;
const MAX_PARTS = 12;

function fromUnits(units) {
  if (!Number.isInteger(units)) {
    throw new Error("units must be an integer count of cents");
  }
  return units;
}

function unitsToText(units) {
  const sign = units < 0 ? "-" : "";
  const magnitude = Math.abs(units);
  const whole = Math.floor(magnitude / CENTS_PER_UNIT);
  const part = magnitude % CENTS_PER_UNIT;
  if (part < 10) {
    return sign + whole + ".0" + part;
  }
  return sign + whole + "." + part;
}

function addAll(amounts) {
  let total = 0;
  for (let i = 0; i < amounts.length; i += 1) {
    total += fromUnits(amounts[i]);
  }
  return total;
}

/// Split `units` into `parts` whole units, giving the remainder to the first
/// lines so the split always sums back to the original amount.
function splitEvenly(units, parts) {
  if (parts < 1 || parts > MAX_PARTS) {
    throw new Error("parts must be between 1 and 12");
  }
  const each = Math.floor(units / parts);
  const rest = units - each * parts;
  const out = [];
  for (let i = 0; i < parts; i += 1) {
    out.push(each + (i < rest ? 1 : 0));
  }
  return out;
}

function percentOf(units, percent) {
  return Math.round((units * percent) / 100);
}

module.exports = {
  CENTS_PER_UNIT,
  fromUnits,
  unitsToText,
  addAll,
  splitEvenly,
  percentOf,
};
