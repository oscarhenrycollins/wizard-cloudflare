---
name: wizard-cloudflare
description: "Use when the owner asks about his Cloudflare accounts (R2 storage, Workers, domains, DNS) or a change to them."
---
# Cloudflare

The owner signs in once inside the Cloudflare app (Wizard link: `/wizard-os-home/?open=wizard-cloudflare`). Never ask for or repeat a Cloudflare token in chat.

1. `cloudflare_connection_status` first: lists logins (`connection_id`) and their accounts (32-hex `account_id`). Nothing connected → tell the owner to open the Cloudflare app and tap "Sign in with Cloudflare".
2. Reads: `cloudflare_resources_read` with `connection_id`, `account_id`, `section`:
   - `r2` (buckets), `r2_objects` (+`bucket`, optional `prefix`), `r2_metadata` (+`bucket`, `key`)
   - `workers`, `worker` (+`script`, settings only)
   - `zones`, `dns` (+`zone` id)
   - `account`, `billing` (billing is a dashboard link only), `registrations`
   Workers/zones/DNS continue with `page`; R2/registrations with `cursor`. `complete: false` means a partial list. Report permission errors; don't treat them as empty.
3. Domains: `cloudflare_registrar_search` (suggestions) and `cloudflare_registrar_check` (availability/price, 1–20 names). Both read-only; nothing is ever bought.
4. Changes (`dns.create`, `dns.update`, `r2.bucket.create`, `r2.object.put`, `workers.deploy`): `cloudflare_action_prepare` with the exact payload. The owner sees one card "Oscar wants to …" in the app and taps Approve or Decline; tell him that in one sentence. Check with `cloudflare_approval_status`; cancel with `cloudflare_approval_cancel`. Changes may be switched off on the box (`writes_disabled`); say so plainly. Domain registration is always blocked.

MCP cannot sign in, confirm, delete, register, create grants or reveal credentials.
