# First installation on another owner's Wizard

This release is portable, but authenticated-shell setup is still explicit. It does not discover or trust the first visiting user, and it does not require the publisher's credentials. Each owner supplies their own exact shell identity and addresses.

## 1. Install with your shell settings

Replace all three example values with your own authenticated Tailscale Serve shell values. The examples are not working addresses. Include every shell port you actually use, comma-separated, in hosts/origins.

```sh
wam install oscarhenrycollins/wizard-cloudflare \
  --set 'WIZARD_OWNER_LOGINS=you@example.com' \
  --set 'WIZARD_TRUSTED_HOSTS=your-box.your-tailnet.ts.net:8796' \
  --set 'WIZARD_TRUSTED_ORIGINS=https://your-box.your-tailnet.ts.net:8796'
```

A normal `wam install` without those settings installs but owner APIs fail closed until configured. Keep this app's `app.env` private (0600). Do not copy another owner's app.env or volume. The OAuth client, scopes (read plus `workers-scripts.write`, `dns.write`, `workers-r2.write`, `workers-r2-bucket-item.write`), shared callback and box-only MCP defaults are already in the public recipe. No API token or OAuth client secret is required.

## 2. Route it inside Wizard

Current Wizard's same-origin gateway uses `~/.wizard-os/links.json`. Preserve its other entries and add/update the Cloudflare entry in its `links` array:

```json
{
  "id": "wizard-cloudflare",
  "name": "Cloudflare",
  "category": "system",
  "port": 18805,
  "path": "/",
  "open": "/wizard-cloudflare/",
  "gateway_strip": true
}
```

Then run `wam links`. This routes the path on the standard 8796 shell. If your authenticated shell also runs on another HTTPS port, add **only** this path on that port:

```sh
tailscale serve --bg --https=8444 --set-path=/wizard-cloudflare/ http://127.0.0.1:18805
```

Use your real shell port instead of 8444. Preserve every other Serve handler; never use `tailscale serve reset`. If a previous plain `wam links` created a dedicated `:18805` Serve listener for this app, remove only that listener (`tailscale serve --https=18805 off`) after the same-origin path works. No public listener or Funnel is needed.

Open `/wizard-os-home/?open=wizard-cloudflare` on your shell. Inspect the Cloudflare frame: it must stay under `/wizard-cloudflare/` on the same origin. The authenticated Serve gateway sets the owner's Tailscale login; an arbitrary reverse proxy that merely forwards user-supplied identity headers is not sufficient. Keep direct app ports private and local administrators/network peers trusted.

## 3. Sign in

Select Sign in with Cloudflare. Consent happens on Cloudflare, not inside the Wizard frame. On the public return page, check that the displayed private box address is yours, then select Return to Wizard. The original app page observes completion. A different browser/cookie, altered state, expiry, cancelled flow or replay is rejected locally.

Only private HTTPS `<box>.<tailnet>.ts.net` origins are supported by this shared return-page release. Custom domains and Cloudflare Access shells require an additional reviewed owner-authentication integration; do not disable the origin/identity checks to make them work.

## Updates and removal

Refresh the catalog source with `wam install oscarhenrycollins/wizard-cloudflare`, then `wam app update wizard-cloudflare` when offered. The fixed local volume `wizard-cloudflare-private-data` retains sign-ins; do not delete it on update. Each machine has its own local volume. Removing the app is not provider-side OAuth revocation; disconnect in the app first if revocation is intended.

## Verification scope

The release was exercised with an empty second container, network and volume on another synthetic shell origin, using anonymous public image pulls and the real shared callback's denial path; state validation, persistence and file modes were checked. Both amd64 and arm64 image layers were pulled anonymously. This is not a second physical-server/ARM runtime test, nor a successful fresh OAuth consent from an unrelated external owner. The existing owner's real OAuth connection and Cloudflare resource reads were preserved after the public-image update. Publisher signing remains a separate human action, not a condition implied by a catalog listing.
