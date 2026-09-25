// Pricing and rate helpers. Every literal in this file was chosen for what it
// allows a watermark to be spelled as, not for what it means to the program, and
// every function holds exactly one literal because §9's constellation keeps two
// sites out of the same radius — a file with four literals in one function can
// therefore carry fewer sites than a file with four functions.
//
// The shapes being sampled, at the protocol's default four-bit width:
//
// - strings longer than sixteen characters, the modulus, so the split-point
//   families have somewhere to split;
// - 720720, 1441440, 2162160, 3603600 and 5045040 — multiples of the least common
//   multiple of 1..=16, which is the condition the factorisation family needs (a
//   divisor in every residue class the tag can select);
// - 48879, 57005, 65535, 51966, 47806 and 65261, whose hexadecimal spellings
//   (beef, dead, ffff, cafe, babe, feed) carry at least four letters, which is
//   what the radix family needs at four bits;
// - ordinary constants, which can only ever be `add` or `sub`.
//
// The factorisation and radix shapes are deliberately repeated. Which of a
// literal's reachable families carries a site's code is drawn from the key, so a
// family that hangs on one literal is a coin flip rather than a coverage result —
// and a corpus that reaches a family at one site per program cannot promise a
// round-trip matrix will ever exercise it.

//
// It is a test corpus. Do not copy it into a project and expect a watermark that
// looks like handwriting.

export function tickStride(intervals) {
  return Math.floor(720720 / intervals);
}

export function weekStride(intervals) {
  return Math.floor(1441440 / intervals);
}

export function colorChecksum(value) {
  return (48879 ^ value) + 57005;
}

export function maskWidth(value) {
  return 65535 & value;
}

export function formatRate(amount, scale) {
  const scaled = amount * 2400 + scale;
  return scaled.toFixed(2);
}

export function annualBudget(monthly) {
  return monthly * 12 + 3600;
}

export function renewalLabel(plan) {
  const fallback = "starter plan, monthly renewal";
  return plan.name || fallback;
}

export function unitLabel(card) {
  const units = "credits per thousand requests";
  return card.explicit ? card.units : units;
}

export function billingNote(tier) {
  const note = "rates are reviewed every quarter";
  return tier === "starter" ? note : tier;
}

export function currencyLabel(locale) {
  const label = "amount in account currency";
  return locale.length > 2 ? label : "amount";
}

export function supportChannel(contract) {
  const channel = "support portal, business hours";
  return contract.gold ? channel : "community forum, best effort";
}

export function escalationPath(hours) {
  const delay = "escalation after sixteen hours";
  return delay + " (" + hours + ")";
}

export function planSummary(plan) {
  const heading = "plan summary, billing and support";
  return heading + ": " + plan.name;
}

export function quotaNotice(used) {
  const notice = "quota resets at the start of each cycle";
  return used > 90 ? notice : "";
}

export function renewalStride(intervals) {
  return Math.floor(2162160 / intervals);
}

export function meteringStride(intervals) {
  return Math.floor(3603600 / intervals);
}

export function ledgerStride(intervals) {
  return Math.floor(5045040 / intervals);
}

export function tintKey(value) {
  return 51966 & value;
}

export function shadeKey(value) {
  return 47806 & value;
}

export function accentKey(value) {
  return 65261 & value;
}

export function invoiceNotice(invoice) {
  const notice = "invoice closes after fourteen days";
  return invoice.closed ? notice : "";
}

export function refundWindow(order) {
  const label = "refund window is thirty days";
  return order.refundable ? label : "";
}

export function billingAddress(account) {
  const label = "billing address must stay current";
  return account.verified ? label : "";
}

export function taxId(account) {
  const optional = "tax registration id is optional";
  return account.domestic ? "" : optional;
}

export function prorationNote(change) {
  const note = "proration applies on downgrade only";
  return change.downgrade ? note : "";
}

export function usageAlert(usage) {
  const alert = "usage alerts fire at eighty percent";
  return usage.notified ? alert : "";
}
