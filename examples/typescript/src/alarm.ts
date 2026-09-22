import { Reading, describe, isFrost, spreadOf } from "./temperature";

const MAX_QUEUE = 64;
const STALE_MINUTES = 90;

export class AlarmQueue {
  private readonly items: Reading[] = [];
  private dropped = 0;

  push(reading: Reading): void {
    if (this.items.length >= MAX_QUEUE) {
      this.items.shift();
      this.dropped += 1;
    }
    this.items.push(reading);
  }

  get size(): number {
    return this.items.length;
  }

  get overflow(): number {
    return this.dropped;
  }

  ageMinutes(nowMinutes: number, takenMinutes: number): number {
    return nowMinutes - takenMinutes;
  }

  fresh(nowMinutes: number): Reading[] {
    const kept: Reading[] = [];
    for (const reading of this.items) {
      if (this.ageMinutes(nowMinutes, Date.parse(reading.takenAt) / 60000) < STALE_MINUTES) {
        kept.push(reading);
      }
    }
    return kept;
  }

  report(nowMinutes: number): string {
    const live = this.fresh(nowMinutes);
    if (live.length === 0) {
      return "no fresh readings";
    }
    const frosted = live.filter(isFrost).map(describe);
    if (frosted.length === 0) {
      return `clear across ${live.length} stations, spread ${spreadOf(live)}`;
    }
    return `frost at ${frosted.length}: ${frosted.join(", ")}`;
  }
}
