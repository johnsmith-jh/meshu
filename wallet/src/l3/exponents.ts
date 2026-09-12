/**
 * Amounts as power-of-two exponents (PROTOCOL.md §6.1, TESTVECTORS vector 1).
 * TS port of core/Exponents.java.
 */
export function toExponents(amount: bigint): number[] {
  if (amount < 0n) throw new Error(`negative amount: ${amount}`);
  const out: number[] = [];
  for (let i = 0; i < 63; i++) {
    if ((amount >> BigInt(i)) & 1n) out.push(i);
  }
  return out;
}

export function fromExponents(exponents: number[]): bigint {
  let amount = 0n;
  for (const e of exponents) {
    if (e < 0 || e > 62) throw new Error(`exponent out of range: ${e}`);
    amount += 1n << BigInt(e);
  }
  return amount;
}

/** Exponent for a single output amount — MUST be a power of two (§6.1). */
export function requirePowerOfTwo(amount: bigint): number {
  if (amount <= 0n || (amount & (amount - 1n)) !== 0n) {
    throw new Error(`output amount not a power of two: ${amount}`);
  }
  let e = 0;
  let a = amount;
  while ((a & 1n) === 0n) {
    a >>= 1n;
    e++;
  }
  return e;
}
