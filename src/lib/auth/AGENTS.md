## Password pages
- Password sign-in, sign-up and set-up run only on /secure/password* documents (full page load, COOP/COEP/CSP from withSecureDocumentHeaders in src/server.ts) through opaque-client.ts and the crypto worker; every password option stays hidden until getAuthProviders reports OPAQUE live. Why: cross-origin isolation needs a hard document boundary, and no dead password button may appear while the deployed database lacks db/0270.

## Sudo Mode
- Sensitive mutations (merge, vault, key/secret rotation) use requireSudo(label): a signed __Host-sudo_session minted only from a general passkey step-up proof, bound to member and sign-in session, valid exactly 300 s from the passkey verification (src/lib/auth/sudo-rules.ts); database-clock passkey proofs stay in addition. Why: one passkey tap covers a short burst of actions without ever trusting a stretched or transplanted window.
