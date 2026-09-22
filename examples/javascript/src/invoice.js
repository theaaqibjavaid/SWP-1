"use strict";

const money = require("./money");
const tax = require("./tax");

const LINE_CAP = 200;
const CURRENCY = "EUR";

function lineTotal(unitPrice, quantity) {
  if (quantity < 1 || quantity > LINE_CAP) {
    throw new Error("quantity must be between 1 and 200");
  }
  return unitPrice * quantity;
}

function subtotal(lines) {
  let sum = 0;
  for (let i = 0; i < lines.length; i += 1) {
    sum += lineTotal(lines[i].unitPrice, lines[i].quantity);
  }
  return sum;
}

function render(lines, region) {
  const before = subtotal(lines);
  const due = tax.taxOf(before, region);
  const rows = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    rows.push(line.label + " " + money.unitsToText(lineTotal(line.unitPrice, line.quantity)));
  }
  rows.push("subtotal " + money.unitsToText(before));
  rows.push("tax " + money.unitsToText(due));
  rows.push("total " + money.unitsToText(before + due));
  return rows.join("\n");
}

function settle(lines, region, payers) {
  const total = subtotal(lines) + tax.taxOf(subtotal(lines), region);
  return money.splitEvenly(total, payers);
}

module.exports = {
  CURRENCY,
  LINE_CAP,
  lineTotal,
  subtotal,
  render,
  settle,
};
