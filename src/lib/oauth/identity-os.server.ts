/**
 * Reads the member's own identity-OS input for userinfo (server-only).
 * From db/0290 it comes from rout_my_identity_claims() in the member's own database context; the
 * primary universal nullifier it returns is used only to derive the per-app nullifier and is never
 * logged, stored or returned. Before 0290 only the public badge booleans are known, so sybil_proof
 * and age_gate answer false (fail closed).
 */
import type { IdentityOsInput } from "./identity-os-scopes";
import { ageVectorFromFloor } from "@/lib/kyc/age-vector";

export async function readIdentityOsInput(userId: string, legalName: IdentityOsInput["legalName"]): Promise<IdentityOsInput> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (await hasSchemaFeature("0290")) {
    const { sql, withDbContext } = await import("@/lib/neon");
    const row = await withDbContext({ userId, workspaceId: null }, async () =>
      ((await sql`select has_legal_identity, is_real_human, age_floor, root_nullifier from public.rout_my_identity_claims()`) as Record<string, unknown>[])[0],
    );
    if (row) {
      const age = row["age_floor"];
      return {
        legalIdentity: row["has_legal_identity"] === true,
        realHuman: row["is_real_human"] === true,
        ageVector: typeof age === "number" ? ageVectorFromFloor(age) : null,
        rootNullifier: typeof row["root_nullifier"] === "string" ? (row["root_nullifier"] as string) : null,
        legalName,
      };
    }
  }
  const { readPublicIdentity } = await import("@/lib/identity/public-identity.server");
  const pub = await readPublicIdentity(userId);
  return { legalIdentity: pub.diditVerified, realHuman: pub.realHuman, ageVector: null, rootNullifier: null, legalName };
}
