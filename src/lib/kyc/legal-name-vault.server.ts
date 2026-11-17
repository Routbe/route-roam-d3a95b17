/**
 * Sealed legal name (server-only). Didit's document name is written only as RPF1 ciphertext into
 * profiles.legal_first_name_sealed / legal_last_name_sealed (db/0287 columns, key ring wrapped by
 * ROUT_VAULT_KEK) through the db/0290 definer rout_kyc_store_legal_name; plaintext never reaches
 * Neon or Didit-side storage. For IBAN holder checks the name is opened in this process only,
 * compared, and dropped: callers get a boolean, never the name.
 */
import { holderMatchesLegalName } from "./legal-name-match";

const FIELDS = ["legal_first_name", "legal_last_name"] as const;

async function live(): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  return (await hasSchemaFeature("0287")) && (await hasSchemaFeature("0290"));
}

/** Seals and stores the member's legal name; false (nothing written) before 0287/0290. Runs in the member's context. */
export async function storeSealedLegalName(userId: string, name: { first: string; last: string }): Promise<boolean> {
  if (!(await live())) return false;
  const { withProfileFieldKeys } = await import("@/lib/profile-private/field-keys.server");
  const { sealProfilePatch } = await import("@/lib/profile-private/sealed-profile");
  const patch = await withProfileFieldKeys((ring) => sealProfilePatch(ring!, userId, { legal_first_name: name.first, legal_last_name: name.last }), { create: true });
  const first = patch["legal_first_name_sealed"];
  const last = patch["legal_last_name_sealed"];
  if (!(first instanceof Uint8Array) || !(last instanceof Uint8Array)) throw new Error("legal_name_seal_failed");
  const { sql } = await import("@/lib/neon");
  const [r] = (await sql`select public.rout_kyc_store_legal_name(${Buffer.from(first)}, ${Buffer.from(last)}) as r`) as { r: string }[];
  if (r?.r !== "ok") throw new Error(`legal_name_store_${r?.r ?? "failed"}`);
  return true;
}

/** Opens a sealed pair in memory and compares it with the account holder; the name never leaves. */
export async function holderMatchesSealed(profileId: string, sealed: { first: unknown; last: unknown }, holder: string): Promise<boolean> {
  if (!(sealed.first instanceof Uint8Array) || !(sealed.last instanceof Uint8Array)) return false;
  const { withProfileFieldKeys } = await import("@/lib/profile-private/field-keys.server");
  const { openProfileRow } = await import("@/lib/profile-private/sealed-profile");
  return withProfileFieldKeys((ring) => {
    if (!ring) return false;
    let opened: Record<string, unknown> | null = openProfileRow(ring, { id: profileId, legal_first_name_sealed: sealed.first, legal_last_name_sealed: sealed.last }, FIELDS);
    try {
      return holderMatchesLegalName(holder, { first: (opened["legal_first_name"] as string | null) ?? null, last: (opened["legal_last_name"] as string | null) ?? null });
    } finally {
      opened = null;
    }
  });
}

/** The caller's own sealed legal name vs. a holder name (personal tip page). False before 0290 or without a sealed name. */
export async function myHolderMatchesSealedName(userId: string, holder: string): Promise<boolean> {
  if (!(await live())) return false;
  const { sql } = await import("@/lib/neon");
  const [row] = (await sql`select first_sealed, last_sealed from public.rout_my_sealed_legal_name()`) as { first_sealed: unknown; last_sealed: unknown }[];
  if (!row) return false;
  return holderMatchesSealed(userId, { first: row.first_sealed, last: row.last_sealed }, holder);
}

/** A workspace owner's sealed legal name vs. a holder name (manager-only definer). */
export async function workspaceOwnerHolderMatches(workspaceId: string, holder: string): Promise<boolean> {
  if (!(await live())) return false;
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select owner_id, first_sealed, last_sealed from public.rout_ws_support_owner_sealed_name(${workspaceId}::uuid)`) as { owner_id: string; first_sealed: unknown; last_sealed: unknown }[];
  for (const r of rows) if (await holderMatchesSealed(r.owner_id, { first: r.first_sealed, last: r.last_sealed }, holder)) return true;
  return false;
}
