/**
 * Unicode confusable skeleton (doc 07 §3.2 `url.idn_homograph`): maps
 * look-alike code points (Cyrillic/Greek homoglyphs, digit substitutions)
 * to a canonical Latin form, plus a couple of multi-char collapses applied
 * to the candidate side only ("rn"→"m", "vv"→"w"). The full confusables
 * table ships in the intel bundle (`confusablesMap`); this is the compiled-in
 * minimal table the bundle extends.
 */

const SINGLE_CHAR: Readonly<Record<string, string>> = Object.freeze({
  // Cyrillic homoglyphs
  "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
  "р": "p", "Р": "P", "с": "c", "С": "C", "х": "x", "Х": "X",
  "у": "y", "У": "Y", "і": "i", "І": "I", "ј": "j", "Ј": "J",
  "ѕ": "s", "Ѕ": "S", "һ": "h", "Һ": "H", "ԁ": "d", "ԍ": "g",
  "ո": "n", "ԛ": "q", "ш": "w", "к": "k", "К": "K", "м": "m",
  "т": "t", "Т": "T", "в": "b", "В": "B", "н": "h", "Н": "H",
  "з": "3", "ч": "4", "я": "r",
  // Greek homoglyphs
  "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ζ": "z",
  "η": "n", "θ": "o", "ι": "i", "κ": "k", "λ": "l", "μ": "u",
  "ν": "v", "ξ": "x", "ο": "o", "π": "n", "ρ": "p", "σ": "o",
  "τ": "t", "υ": "u", "φ": "p", "χ": "x", "ψ": "w", "ω": "w",
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
  "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
  "Υ": "Y", "Χ": "X",
  // Digit / symbol substitutions
  "0": "o", "1": "l", "!": "i", "|": "l", "ƒ": "f",
  // Full-width Latin
  "ａ": "a", "ｅ": "e", "ｏ": "o", "ｐ": "p", "ｃ": "c", "ｘ": "x",
});

/** Multi-char collapses applied to the candidate side only. */
const MULTI_CHAR: ReadonlyArray<[string, string]> = Object.freeze([
  ["rn", "m"],
  ["vv", "w"],
  ["cl", "d"],
]) as unknown as ReadonlyArray<[string, string]>;

/**
 * Compute the confusable skeleton of a host/domain string.
 * `extra` merges the bundle's confusablesMap over the compiled-in table.
 */
export function skeleton(input: string, extra: Readonly<Record<string, string>> = {}): string {
  let out = "";
  for (const ch of input.toLowerCase()) {
    out += extra[ch] ?? SINGLE_CHAR[ch] ?? ch;
  }
  for (const [from, to] of MULTI_CHAR) {
    out = out.split(from).join(to);
  }
  return out;
}
