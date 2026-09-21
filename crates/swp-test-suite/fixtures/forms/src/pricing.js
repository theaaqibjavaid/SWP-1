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
// - 720720 and 1441440, the least common multiple of 1..=16 and its double, which
//   is the condition the factorisation family needs (a divisor in every residue
//   class the tag can select);
// - 48879, 57005 and 65535, whose hexadecimal spellings (beef, dead, ffff) carry
//   four letters, which is what the radix family needs at four bits;
// - ordinary constants, which can only ever be `add` or `sub`.
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
