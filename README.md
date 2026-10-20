# Cloudflare for Wizard (Testing)

A read-only connection to your own Cloudflare accounts, inside your own Wizard. Each owner's app runs on their box and contacts Cloudflare directly. The page and agent never receive provider tokens.

## Available now

- Several named Cloudflare sign-ins and explicit account selection.
- R2 buckets, bounded object lists and metadata (not private object downloads).
- Workers scripts/settings; account-bound zones and DNS records.
- Registrar search, availability checks and registrations where Cloudflare grants access.
- Contextual links to Cloudflare's own billing dashboard.
- A narrow MCP interface for the agent on your box.

**Testing release, not dashboard parity. Changes and purchases are disabled in the shipped recipe.** Signup, payment methods, account agreements and billing stay on Cloudflare's own website. There is no account-creation automation, payment-card handling or backup scheduler.

## Install

```sh
wam install oscarhenrycollins/wizard-cloudflare
```

The public recipe uses the shared public PKCE client and callback automatically. It needs no publisher API token, client secret or per-owner OAuth registration. Before using the page, configure the following app settings for **your** Wizard's authenticated Tailscale Serve shell:

- `WIZARD_OWNER_LOGINS`: your exact Tailscale login, not every tailnet member.
- `WIZARD_TRUSTED_HOSTS`: exact shell hosts, including ports (comma-separated).
- `WIZARD_TRUSTED_ORIGINS`: the matching `https://` origins (comma-separated).

Open it from the Wizard launcher, at `/wizard-os-home/?open=wizard-cloudflare`, not a separate app port. The shell gateway must route `/wizard-cloudflare/` to this app with its prefix stripped and preserve the authenticated Tailscale identity; use the supported `wam links` gateway configuration. Callback origins are limited to private HTTPS `<box>.<tailnet>.ts.net` addresses, any valid shell port. Custom domains/Cloudflare Access are not yet supported by this return-page release. An unconfigured owner boundary fails closed rather than trusting the first visitor. An alternate authenticated gateway can inject a server-only `X-Wizard-Owner-Token`; never put it in browser JavaScript.

Only the owner should have network access to the box. Host administrators, local applications and Docker-network peers are trusted infrastructure: a forged HTTP Host is not remote peer attestation. MCP is box-only by default and refuses browser/forwarding headers; configure a separate admin bearer for another trusted transport.

Sign in opens Cloudflare's consent in a top-level tab. The shared return page shows your box address; select **Return to Wizard** only if it is your own. The original app window observes completion. Cancel invalidates the flow. A user who has no account can create one at https://dash.cloudflare.com/sign-up; enable products or manage billing only on Cloudflare's site after reviewing their terms and prices.

## Sign-in and privacy

The app generates a fresh random verifier and one-use state per login, binds the entire state hash to the local browser's HttpOnly cookie, and retains the verifier on the box. The stateless return page at `https://www.aiwizards.com/wizard-cloudflare/auth/callback` sees the authorization code and return address. It cannot exchange that code without the box's private verifier. It has no storage, request logging, analytics or token exchange. It is not an authentication authority: tampered state and the wrong local browser are rejected by the box. The code goes to the exact callback path on a private HTTPS Tailscale host only after an explicit, host-labelled user click; arbitrary public websites and URL credentials are refused.

The box exchanges codes directly with Cloudflare using the exact registered shared redirect URI and its private verifier. Tokens, verifier and refresh credentials never pass through the relay or public UI. Codes necessarily travel through callback URLs; app/Worker request logging is disabled and responses use no-store/no-referrer. Provider and network infrastructure remain within their own privacy policies.

State, expiry, cancellation, session generations and one-use exchange barriers fail closed. Refresh tokens may be single use: the app serializes rotation and writes a durable in-flight barrier before calling Cloudflare. An interrupted/ambiguous rotation requires sign-in rather than retrying a possibly consumed token. Do not run a second refresher against these credentials.

The app's named Docker volume `wizard-cloudflare-private-data` preserves sign-ins through updates. Data directory permissions are 0700 and files 0600. Credentials are access-controlled, **not encrypted at rest**; protect your box and backups. Do not delete or share that volume. Each box has a separate local volume; this is not pooled Cloudflare access.

Requested scopes: `offline_access account-settings.read workers-r2.read workers-r2-bucket-item.read workers-scripts.read zone.read dns.read registrar-domains.read`. No write, purchase, billing-write or `openid` permission is requested.

## Development and verification

Runtime uses Python's standard library; image supports Linux amd64 and arm64. Build with `docker build -f app/Dockerfile .`. Tests use synthetic provider transports and make no Cloudflare calls:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node relay/test.mjs
wam check .
wam check . --proposal
```

Browser tests additionally require `playwright-core` (set `PLAYWRIGHT_MODULE` if necessary) and Chrome (`CHROME_PATH`). Production authentication is absent from fixtures. `CF_DEVELOPMENT_MODE=loopback-single-owner` is for isolated loopback fixtures only and is never enabled in the public recipe.

Images are built in GitHub Actions from public source, then pinned by multiarchitecture digest in `runtipi/docker-compose.yml`. Publication uses the supported discovery index at https://apps.aiwizards.com and store at https://www.aiwizards.com/wizard-apps. A public listing is not a signed publisher identity; signing is a separate owner action in Wizard's signing sheet.

See `openapi.json` and `skill/SKILL.md` for the API/MCP contract. Future Backups is a separate consumer and is not included. Do not enable the optional implementation-only write paths without a separately reviewed provider mutation release. Registrar purchase remains blocked regardless of configuration.
