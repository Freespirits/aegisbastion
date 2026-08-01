/**
 * Token re-authorization loop (docs 01 §5.5, 03 §9.2, 11 §3.2; Ruling C5).
 *
 * Long-running work (watches, campaigns, stress tests) re-authorizes mid-run:
 * RefreshToken makes gatekeeper re-run the policy check and mint a SUCCESSOR
 * token bound to the same task_id. There is no unauthenticated refresh —
 * a denial (empty successor) means halt when the current token expires, and a
 * transport failure means the current unexpired token keeps working until it
 * does (doc 11 §7), after which the module halts.
 *
 * The loop refreshes at min(TTL/2, exp - 60s) so a successor is always in
 * hand before the current token expires, and retries transport errors with
 * capped backoff. Re-authorization denial fires `onDenied` once and stops the
 * loop — the PEP guard refuses new target touches at token expiry regardless.
 */

import { decodeJwt } from "jose";
import { PepError } from "./errors.js";

export interface ReauthorizationCallbacks {
  /** Called with each successor token; swap it into the running task. */
  onSuccessor: (token: string) => void;
  /** Re-authorization was denied — halt when the current token expires. */
  onDenied?: () => void;
  /** Transport-level refresh failure (kept retrying until expiry). */
  onRefreshError?: (err: unknown) => void;
}

export interface TokenReauthorizerOptions {
  /**
   * Performs the RefreshToken RPC. Injected so the loop stays
   * transport-agnostic (and unit-testable). Returns the successor token, or
   * "" when re-authorization was denied.
   */
  refresh: (currentToken: string) => Promise<string>;
  /** Test hook: override "now" (ms). */
  nowMs?: () => number;
  /** Test hook: override sleep. */
  sleep?: (ms: number) => Promise<void>;
}

const REFRESH_MARGIN_MS = 60_000;
const MIN_DELAY_MS = 5_000;
const MAX_BACKOFF_MS = 60_000;

export class TokenReauthorizer {
  private stopped = false;
  private loop: Promise<void> | null = null;

  constructor(private readonly opts: TokenReauthorizerOptions) {}

  private now(): number {
    return this.opts.nowMs?.() ?? Date.now();
  }

  private sleep(ms: number): Promise<void> {
    return this.opts.sleep?.(ms) ?? new Promise((r) => setTimeout(r, ms));
  }

  /**
   * Run the loop until stop() or a re-authorization denial. `currentToken`
   * is a getter because the successor becomes the next iteration's input.
   */
  start(getCurrentToken: () => string, cb: ReauthorizationCallbacks): void {
    if (this.loop !== null) throw new Error("TokenReauthorizer already started");
    this.stopped = false;
    this.loop = this.run(getCurrentToken, cb).catch((err: unknown) => {
      cb.onRefreshError?.(err);
    });
  }

  async stop(): Promise<void> {
    this.stopped = true;
    await this.loop;
  }

  private tokenExpMs(token: string): number {
    try {
      const { exp } = decodeJwt(token);
      if (typeof exp === "number") return exp * 1000;
    } catch {
      // fall through
    }
    throw new PepError("TOKEN_MALFORMED", "cannot decode exp from current token");
  }

  private async run(getCurrentToken: () => string, cb: ReauthorizationCallbacks): Promise<void> {
    let backoff = MIN_DELAY_MS;
    for (;;) {
      if (this.stopped) return;
      const current = getCurrentToken();
      const expMs = this.tokenExpMs(current);
      const now = this.now();
      // Refresh at the earlier of half the remaining life or exp - 60 s.
      const ttlRemaining = expMs - now;
      if (ttlRemaining <= 0) return; // already expired — the PEP guard refuses
      const waitMs = Math.max(
        MIN_DELAY_MS,
        Math.min(ttlRemaining / 2, ttlRemaining - REFRESH_MARGIN_MS),
      );
      await this.sleep(waitMs);
      if (this.stopped) return;

      let successor: string;
      try {
        successor = await this.opts.refresh(getCurrentToken());
      } catch (err) {
        // Transport failure: existing unexpired token keeps working (doc 11
        // §7). Back off and retry while time remains.
        cb.onRefreshError?.(err);
        const remaining = this.tokenExpMs(getCurrentToken()) - this.now();
        if (remaining <= MIN_DELAY_MS) return;
        await this.sleep(Math.min(backoff, remaining / 2));
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
        continue;
      }
      backoff = MIN_DELAY_MS;
      if (successor === "") {
        // Re-authorization DENIED (policy re-check failed — RoE revoked,
        // approval lapsed, …). Halt when the current token expires.
        cb.onDenied?.();
        return;
      }
      cb.onSuccessor(successor);
    }
  }
}
