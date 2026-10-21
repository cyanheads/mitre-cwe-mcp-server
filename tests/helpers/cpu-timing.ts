/**
 * @fileoverview Thread-CPU growth assertions for scanners over caller- or catalog-sized text.
 * @module tests/helpers/cpu-timing
 */
import { expect } from 'vitest';

/** Thread CPU milliseconds per call: the best of three samples, short calls repeated until measurable. */
function cpuMilliseconds(run: () => unknown): number {
  let best = Number.POSITIVE_INFINITY;
  for (let sample = 0; sample < 3; sample++) {
    const start = process.threadCpuUsage();
    let calls = 0;
    let elapsed = 0;
    do {
      run();
      calls++;
      const used = process.threadCpuUsage(start);
      elapsed = (used.user + used.system) / 1000;
    } while (elapsed < 2 && calls < 100);
    best = Math.min(best, elapsed / calls);
  }
  return best;
}

/**
 * Assert linear growth from 5,000 to 320,000 input characters. The size doubles each step, and
 * each size must finish within 1 µs of thread CPU per character plus 20 ms before the next runs,
 * so a quadratic regression fails within seconds. Across the full 64× span the time ratio stays
 * below 256: linear growth gives 64, quadratic 4,096.
 */
export function expectLinearTime<T>(
  label: string,
  build: (length: number) => T,
  run: (input: T) => unknown,
): void {
  const smallest = 5_000;
  const largest = 320_000;
  run(build(smallest));
  const times: number[] = [];
  for (let length = smallest; length <= largest; length *= 2) {
    const input = build(length);
    const milliseconds = cpuMilliseconds(() => run(input));
    expect(milliseconds, `${label}: ${length} characters`).toBeLessThan(20 + length / 1000);
    times.push(milliseconds);
  }
  const ratio = (times.at(-1) as number) / (times[0] as number);
  expect(ratio, `${label}: growth over the 64× span`).toBeLessThan(256);
}
