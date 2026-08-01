/**
 * Token re-authorization loop (doc 11 §3.2: RefreshToken is mid-run
 * re-authorization — policy re-check, then a successor token; denial → halt).
 */

import { describe, expect, it } from "vitest";
import { TokenReauthorizer } from "../src/refresh.js";
import { makeKey, signToken, NOW } from "./helpers.js";

const instantSleep = async () => {};

describe("TokenReauthorizer", () => {
  it("delivers a successor token before expiry", async () => {
    const key = await makeKey("gk-a");
    const current = await signToken(key, { exp: NOW + 100 });
    const successor = await signToken(key, { jti: "tok_2", exp: NOW + 190 });

    const reauth = new TokenReauthorizer({
      refresh: async () => successor,
      nowMs: () => NOW * 1000,
      sleep: instantSleep,
    });
    const delivered = await new Promise<string>((resolve) => {
      reauth.start(
        () => current,
        {
          onSuccessor: (t) => {
            void reauth.stop().then(() => resolve(t));
          },
        },
      );
    });
    expect(delivered).toEqual(successor);
  });

  it("fires onDenied and stops when re-authorization is denied (empty successor)", async () => {
    const key = await makeKey("gk-a");
    const current = await signToken(key, { exp: NOW + 100 });

    let denied = 0;
    const reauth = new TokenReauthorizer({
      refresh: async () => "",
      nowMs: () => NOW * 1000,
      sleep: instantSleep,
    });
    await new Promise<void>((resolve) => {
      reauth.start(() => current, {
        onSuccessor: () => {},
        onDenied: () => {
          denied++;
          resolve();
        },
      });
    });
    await reauth.stop();
    expect(denied).toBe(1);
  });

  it("retries transport errors with backoff, then succeeds", async () => {
    const key = await makeKey("gk-a");
    const current = await signToken(key, { exp: NOW + 100 });
    const successor = await signToken(key, { jti: "tok_2", exp: NOW + 190 });

    let errors = 0;
    let calls = 0;
    const reauth = new TokenReauthorizer({
      refresh: async () => {
        calls += 1;
        if (calls === 1) throw new Error("gatekeeper unreachable");
        return successor;
      },
      nowMs: () => NOW * 1000,
      sleep: instantSleep,
    });
    const delivered = await new Promise<string>((resolve) => {
      reauth.start(
        () => current,
        {
          onSuccessor: (t) => {
            void reauth.stop().then(() => resolve(t));
          },
          onRefreshError: () => errors++,
        },
      );
    });
    expect(errors).toBe(1);
    expect(delivered).toEqual(successor);
    expect(calls).toBe(2);
  });

  it("does nothing for an already-expired token (the PEP guard refuses)", async () => {
    const key = await makeKey("gk-a");
    const current = await signToken(key, { iat: NOW - 2000, exp: NOW - 1100 });

    let calls = 0;
    const reauth = new TokenReauthorizer({
      refresh: async () => {
        calls += 1;
        return "";
      },
      nowMs: () => NOW * 1000,
      sleep: instantSleep,
    });
    reauth.start(() => current, { onSuccessor: () => {} });
    await reauth.stop();
    expect(calls).toBe(0);
  });
});
