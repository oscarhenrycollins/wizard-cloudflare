---
wizard: 0.2
id: wizard-cloudflare
name: Cloudflare (Testing)
type: external
category: system
version: 1.3.0-testing
summary: "Read-only Cloudflare accounts: storage, Workers and domains. Testing."
license: GPL-3.0-only
source: https://github.com/oscarhenrycollins/wizard-cloudflare
runtime:
  kind: runtipi
  config: runtipi/config.json
  compose: runtipi/docker-compose.yml
api:
  port: 18805
  path: /api
  spec: openapi.json
mcp:
  path: /mcp
  port: 18805
  transport: streamable-http
skill: skill/SKILL.md
view:
  path: /
  port: 18805
  source:
    path: web
    build: python3 app/build_view.py
    dist: web
provides: [cloudflare-connection]
system: true
uses: []
needs: []
health: /healthz
icon: icon.png
---

# Cloudflare

Sign in with Cloudflare to see your accounts' storage (R2), Workers and domains inside Wizard. Testing release: provider changes and purchases are disabled; billing and signup remain provider-hosted. Tokens stay on your box. A stateless shared callback page sees codes but cannot exchange them without the box's private verifier. Configure your own exact shell hosts, origins and owner login; no publisher secrets are needed. Backups are not included.

- Provides `cloudflare-connection` (contract `wizard.cloudflare-connection/1`); several logins and accounts.
- Opened inside the Wizard shell at `/wizard-cloudflare/`; the owner is the signed-in tailnet user named by Tailscale Serve (`WIZARD_OWNER_LOGINS`), plus exact Host/Origin checks and CSRF on every write.
- MCP at `/mcp` for the agent on this box: reads, plus preparing changes the owner approves in the app. It never connects, confirms or reveals credentials.
- Provider writes stay off unless `CF_ALLOW_WRITES=true`; domain registration is always blocked.
