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
