/**
 * Optimal-string-alignment Damerau–Levenshtein distance — used by
 * `url.typosquat` (doc 07 §3.2: distance ≤ 2 to any brand domain).
 * Pure, allocation-light, early-exit on a max-distance bound.
 */
export function damerauLevenshtein(a: string, b: string, maxDistance = Infinity): number {
  const alen = a.length;
  const blen = b.length;
  if (Math.abs(alen - blen) > maxDistance) return maxDistance === Infinity ? Math.abs(alen - blen) : maxDistance + 1;
  if (alen === 0) return blen;
  if (blen === 0) return alen;

  let prev2: number[] | undefined;
  let prev: number[] = new Array<number>(blen + 1);
  let curr: number[] = new Array<number>(blen + 1);
  for (let j = 0; j <= blen; j++) prev[j] = j;

  for (let i = 1; i <= alen; i++) {
    curr[0] = i;
    let rowMin = curr[0] ?? Infinity;
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= blen; j++) {
      const cost = ca === b.charCodeAt(j - 1) ? 0 : 1;
      let v = Math.min(
        (prev[j] ?? 0) + 1, // deletion
        (curr[j - 1] ?? 0) + 1, // insertion
        (prev[j - 1] ?? 0) + cost, // substitution
      );
      if (i > 1 && j > 1 && ca === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
        v = Math.min(v, (prev2?.[j - 2] ?? 0) + cost); // transposition
      }
      curr[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > maxDistance) return maxDistance + 1;
    prev2 = prev;
    prev = curr;
    curr = new Array<number>(blen + 1);
  }
  return prev[blen] ?? 0;
}
