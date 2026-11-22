# Optional Auth0 login

**Status: VERIFIED against a real Auth0 tenant, in mock mode with no key attached (2026-11-22).** Not verified: logout, token refresh, page-reload behavior, and the login with the physical key attached. It is **off by default**. With no variables set, the dashboard and gateway behave exactly as they did before.

## What it does (and does not)

When on:
- The dashboard shows a "Sign in" screen first. After login it sends `Authorization: Bearer <access token>` on its POST requests.
- The gateway requires a valid token on **`POST /approvals/{id}`** and **`POST /rewind`**. Missing, malformed, expired, wrongly signed, wrong-audience or wrong-issuer tokens get **401**. If the tenant's signing keys cannot be fetched (for example, no internet) it also fails closed with 401.
- Only RS256 is accepted, so `alg: none` and HS256-with-the-public-key tricks fail.

It never touches:
- **The physical key.** The key talks to the gateway over USB serial with its own HMAC, not HTTP. Auth0 cannot gate it, block it or stand in for it.
- **The critical-action rule.** A valid token does not let the dashboard approve a critical action while a key is attached. The gateway still answers 409 (tested).
- **`/unfreeze`, `/autonomy` and `/tasks`** are behind the same login (red-team fix: they were open, so with the login on anyone local could still unfreeze the agent or start a task). `run_demo.py` and other scripts that call them need a token when the login is on.
- Everything else stays open: `/state`, `/events`, `/ws`, `/freeze` (freezing only makes things safer, so it is deliberately open), `/internal/proxy-event` and `/external/submit` (machine endpoints; see `AIRLOCK_EXTERNAL_TOKEN`).

The gateway binds `127.0.0.1` and is still a demo-grade, single-user setup. This adds a login gate to two endpoints. It is not a full access-control layer.

## What to create in the Auth0 dashboard

1. **Tenant.** Any tenant works. Note its domain, for example `your-tenant.us.auth0.com`.
2. **Application**: Applications, Create Application, type **Single Page Web Applications**. In Settings set all three to `http://localhost:5173`:
   - Allowed Callback URLs
   - Allowed Logout URLs
   - Allowed Web Origins

   Copy the **Client ID**. (A SPA has no secret; do not put one anywhere.)
3. **API**: Applications, APIs, Create API. Pick an **Identifier**, for example `https://airlock.local/api`. This string is the *audience*; it does not have to be a reachable URL. Set the **signing algorithm to RS256** (the gateway accepts nothing else).
4. **A user** who can log in: User Management, Users, Create User (or use whichever connection you prefer). Consider turning off sign-ups for the database connection so only people you created can log in.
5. If you want it on the demo machine only, nothing else is needed. For another host or port, add that origin to the three URL lists in step 2 and see `allow_origins` in `gateway/airlock/server.py` (it allows `localhost:5173` and `127.0.0.1:5173` only).

## Environment variables

Gateway (both, or neither; with only one set the gateway **refuses to start**):

| Variable | Value |
|---|---|
| `AUTH0_DOMAIN` | `your-tenant.us.auth0.com` (a leading `https://` is stripped) |
| `AUTH0_AUDIENCE` | the API Identifier from step 3 |

Dashboard (Vite reads these at start; restart `npm run dev` after changing). Put them in `dashboard/.env.local` (not committed; see `dashboard/.env.example`) or export them in the shell that runs `make demo`:

| Variable | Value |
|---|---|
| `VITE_AUTH0_DOMAIN` | the same domain |
| `VITE_AUTH0_CLIENT_ID` | the Client ID from step 2 |
| `VITE_AUTH0_AUDIENCE` | **the same value as `AUTH0_AUDIENCE`**. Required in practice: without it Auth0 issues an opaque token the gateway cannot validate, and every approve and rewind returns 401. |

The login is enabled only when both `VITE_AUTH0_DOMAIN` and `VITE_AUTH0_CLIENT_ID` are set.

## Turn it on

```
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_AUDIENCE=https://airlock.local/api
export VITE_AUTH0_DOMAIN=$AUTH0_DOMAIN
export VITE_AUTH0_CLIENT_ID=<client id>
export VITE_AUTH0_AUDIENCE=$AUTH0_AUDIENCE
make demo            # or make server and make dashboard
```

Automated check (needs the gateway running with the same two variables; reads no secrets, prints PASS / FAIL / SKIP per line and a RESULT, exits non-zero on FAIL; SKIP when the variables are unset):

```
make auth0-check
```

It covers the tenant's JWKS, `auth_required`, and 401 with no or a garbage token. It does not log in, so it does not make this VERIFIED.

Manual check: `curl -s localhost:8000/state` shows `"auth_required": true`. Open the dashboard, sign in, run the attack task and use Deny, then Rewind. Without logging in, `curl -X POST localhost:8000/rewind -d '{}' -H 'Content-Type: application/json'` must return 401.

## Turn it off

Unset all five variables (and delete `dashboard/.env.local` if you used it), then restart. `auth_required` is `false` and no login screen appears.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Gateway exits at start with "must both be set, or neither" | only one of `AUTH0_DOMAIN` / `AUTH0_AUDIENCE` is set |
| Login works, but approve and rewind give "login required or session expired" (401) | `VITE_AUTH0_AUDIENCE` missing or different from `AUTH0_AUDIENCE`; API not set to RS256; the gateway cannot reach `https://<domain>/.well-known/jwks.json` |
| Auth0 error "callback URL mismatch" | Step 2 URLs do not match the address in the browser (use `localhost`, not `127.0.0.1`, or add both) |
| Auth0 error "Callback URL mismatch" on the real tenant | the three URI fields (Allowed Callback URLs, Allowed Logout URLs, Allowed Web Origins) are not set on the SPA, or you are using the wrong app: it must be the Single Page Application, not the machine-to-machine test app |
| Auth0 error "Client is not authorized to access resource server" | set the API's User-delegated Access to allow, or authorize the app in the API's Application Access tab |
| Reloading the page asks you to sign in again | by design: the dashboard keeps the session in memory only (`cacheLocation="memory"`), nothing in browser storage |

## What was actually run

**Against a real tenant, 2026-11-22** (`<your-tenant>.us.auth0.com`, a SPA plus a custom API with RS256; mock mode, no key attached; run by hand):

- Sign in worked.
- Resume agent, change autonomy and start task worked behind the login.
- Approve and Deny both worked on a `write_file` approval.
- Rewind restored snapshot `s0001`.
- `make auth0-check` passed 7/7: the real JWKS with 2 RS256 keys, `auth_required` true, and 401 with no token and with a garbage token.

**Without a real tenant** (run earlier, still stand):

- `gateway/tests/test_auth0.py` (15 tests, part of `make test`, no network): a locally generated RSA key stands in for the tenant. Disabled by default needs no token; enabled rejects a missing token, empty value, garbage, wrong key, wrong audience, wrong issuer, expired, no `exp`, HS256 and `alg: none` on both approve and rewind (and leaves the approval pending); a valid token works; an unreachable key set fails closed; a valid token still gets 409 on a critical action with a key attached; a half-configured gateway refuses to start.
- Dashboard: `npm run build` passes. With fake values (`VITE_AUTH0_DOMAIN=tenant.example.auth0.com`, a made-up client id) the dev server showed the "Sign in" screen and hid the app; with no values it showed the app exactly as before (checked once, in Google Chrome driven by Playwright).

**Not run:** logout, token refresh, page-reload behavior, and the login with the physical key attached.
