export const ABSOLUTE_ZERO = 273.15;
export const BOILING = 100;

export interface Reading {
  readonly station: string;
  readonly celsius: number;
  readonly takenAt: string;
}

export function toFahrenheit(celsius: number): number {
  return celsius * 1.8 + 32;
}

export function toKelvin(celsius: number): number {
  return celsius + ABSOLUTE_ZERO;
}

export function isFrost(reading: Reading): boolean {
  return reading.celsius <= 0;
}

export function isHeatWarning(reading: Reading): boolean {
  return reading.celsius >= BOILING;
}

export function meanOf(readings: readonly Reading[]): number {
  if (readings.length === 0) {
    throw new Error("meanOf needs at least one reading");
  }
  let sum = 0;
  for (const reading of readings) {
    sum += reading.celsius;
  }
  return Math.round((sum / readings.length) * 10) / 10;
}

export function spreadOf(readings: readonly Reading[]): number {
  let low = readings[0].celsius;
  let high = readings[0].celsius;
  for (let i = 1; i < readings.length; i += 1) {
    const value = readings[i].celsius;
    if (value < low) {
      low = value;
    }
    if (value > high) {
      high = value;
    }
  }
  return high - low;
}

export function describe(reading: Reading): string {
  const flags: string[] = [];
  if (isFrost(reading)) {
    flags.push("frost");
  }
  if (isHeatWarning(reading)) {
    flags.push("boiling");
  }
  if (flags.length === 0) {
    return `${reading.station} ${reading.celsius.toFixed(1)}`;
  }
  return `${reading.station} ${reading.celsius.toFixed(1)} ${flags.join("+")}`;
}
