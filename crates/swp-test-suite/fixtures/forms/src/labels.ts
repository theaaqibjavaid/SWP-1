// The TypeScript spelling, which exists so the matrix says something about a
// language whose literals sit beside type annotations. Same one-literal-per-
// function rule as the other two files.

export interface RateCard {
  units: string;
  explicit: boolean;
}

export function tickStride(intervals: number): number {
  return Math.floor(720720 / intervals);
}

export function colorChecksum(value: number): number {
  return (48879 ^ value) + 57005;
}

export function formatRate(amount: number, scale: number): string {
  const scaled = amount * 2400 + scale;
  return scaled.toFixed(2);
}

export function annualBudget(monthly: number): number {
  return monthly * 12 + 3600;
}

export function unitLabel(card: RateCard): string {
  const units = "credits per thousand requests";
  return card.explicit ? card.units : units;
}

export function renewalLabel(plan: { name?: string }): string {
  const fallback = "starter plan, monthly renewal";
  return plan.name ?? fallback;
}

export function billingNote(tier: string): string {
  const note = "rates are reviewed every quarter";
  return tier === "starter" ? note : tier;
}

export function supportChannel(gold: boolean): string {
  return gold ? "support portal, business hours" : "community forum, best effort";
}

export function renewalStride(intervals: number): number {
  return Math.floor(2162160 / intervals);
}

export function meteringStride(intervals: number): number {
  return Math.floor(3603600 / intervals);
}

export function ledgerStride(intervals: number): number {
  return Math.floor(5045040 / intervals);
}

export function tintKey(value: number): number {
  return 51966 & value;
}

export function shadeKey(value: number): number {
  return 47806 & value;
}

export function accentKey(value: number): number {
  return 65261 & value;
}

export function invoiceNotice(invoice: { closed: boolean }): string {
  const notice = "invoice closes after fourteen days";
  return invoice.closed ? notice : "";
}

export function refundWindow(order: { refundable: boolean }): string {
  const label = "refund window is thirty days";
  return order.refundable ? label : "";
}

export function billingAddress(account: { verified: boolean }): string {
  const label = "billing address must stay current";
  return account.verified ? label : "";
}

export function taxId(account: { domestic: boolean }): string {
  const optional = "tax registration id is optional";
  return account.domestic ? "" : optional;
}

export function prorationNote(change: { downgrade: boolean }): string {
  const note = "proration applies on downgrade only";
  return change.downgrade ? note : "";
}

export function usageAlert(usage: { notified: boolean }): string {
  const alert = "usage alerts fire at eighty percent";
  return usage.notified ? alert : "";
}
