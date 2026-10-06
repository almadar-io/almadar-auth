# @almadar/auth

App-user identity for Almadar apps.

- `@almadar/auth`: `VerifiedUser`, `AuthOutcome`, and `resolveViewer` (verified user → `@user`, onto the program's `[identity]` entity).
- `@almadar/auth/server`: token verifiers (Firebase / Identity Platform, generic OIDC), `authenticateBearer`, `verifierFromEnv`, and the OIDC client used by sign-in and by the `oauth` integration.

Reference: `docs/Almadar_Auth.md` in the Almadar monorepo.
