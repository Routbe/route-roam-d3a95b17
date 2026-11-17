/**
 * Sovereign Identity OS scopes for "Login met ROUT" (pure, browser-safe, tested).
 *
 *   sybil_proof     app_nullifier = BLAKE3("rout.app_nullifier.v1" 0x00 universal_nullifier 0x00 client_id):
 *                   one human = one account per app, and two apps cannot link their users.
 *   real_human      is_real_human, true only from a zero-knowledge humanity proof (green shield).
 *   age_gate:N      age_over_N for N = 13..21 (the app picks one), from the capped age floor of a KYC
 *                   attestation; no date of birth leaves ROUT. A signed claim, not a zk-SNARK.
 *   legal_identity  has_legal_identity, plus the legal name only where ROUT still holds one (legacy
 *                   tier-2 records); Didit attestations since 2026-11-17 keep no name, so it is null.
 *                   Off by default on the consent screen: the member must tick it.
 */
import { blake3 } from "@noble/hashes/blake3.js";
import { ageGatePasses, AGE_GATE_MAX, AGE_GATE_MIN } from "@/lib/kyc/age-vector";

export const AGE_GATE_SCOPES = Array.from({ length: AGE_GATE_MAX - AGE_GATE_MIN + 1 }, (_, i) => `age_gate:${AGE_GATE_MIN + i}`);
export const IDENTITY_OS_SCOPES: readonly string[] = ["sybil_proof", "real_human", "legal_identity", ...AGE_GATE_SCOPES];

/** The minimum age of an age_gate:N scope, or null for any other string. */
export function ageGateMin(scope: string): number | null {
  const m = /^age_gate:(\d{2})$/.exec(scope);
  if (!m) return null;
  const n = Number(m[1]);
  return n >= AGE_GATE_MIN && n <= AGE_GATE_MAX ? n : null;
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Per-app nullifier; deterministic for (person, app), unlinkable across apps. */
export function appNullifier(universalNullifier: string, clientId: string): string {
  if (!HEX64.test(universalNullifier)) throw new Error("app_nullifier_input");
  if (!clientId || clientId.length > 200) throw new Error("app_nullifier_input");
  const msg = new TextEncoder().encode(`rout.app_nullifier.v1\u0000${universalNullifier}\u0000${clientId}`);
  return [...blake3(msg)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export type IdentityOsInput = {
  legalIdentity: boolean;
  realHuman: boolean;
  /** Age-threshold vector (kyc/age-vector.ts); null without a KYC attestation. */
  ageVector: number | null;
  /** The member's primary universal nullifier; null without a KYC attestation (or before db/0290). */
  rootNullifier: string | null;
  legalName: { first_name: string | null; last_name: string | null; full_legal_name: string | null } | null;
};

/** Claims for the granted identity-OS scopes and the scopes that were answered (for the disclosure log). */
export function identityOsClaims(granted: readonly string[], clientId: string, input: IdentityOsInput): { claims: Record<string, unknown>; disclosed: string[] } {
  const claims: Record<string, unknown> = {};
  const disclosed: string[] = [];
  if (granted.includes("sybil_proof")) {
    const n = input.rootNullifier && HEX64.test(input.rootNullifier) ? appNullifier(input.rootNullifier, clientId) : null;
    claims["sybil_proof"] = n !== null;
    if (n) claims["app_nullifier"] = n;
    disclosed.push("sybil_proof");
  }
  if (granted.includes("real_human")) {
    claims["is_real_human"] = input.realHuman === true;
    disclosed.push("real_human");
  }
  for (const scope of granted) {
    const min = ageGateMin(scope);
    if (min === null) continue;
    claims[`age_over_${min}`] = ageGatePasses(input.ageVector, min);
    disclosed.push(scope);
  }
  if (granted.includes("legal_identity")) {
    claims["has_legal_identity"] = input.legalIdentity === true;
    if (input.legalIdentity && input.legalName?.full_legal_name) Object.assign(claims, input.legalName);
    disclosed.push("legal_identity");
  }
  return { claims, disclosed };
}
