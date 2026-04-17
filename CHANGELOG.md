# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.8.0] — 2026-04-13

- security: add proof parameter to all tools with npub
- update debit_or_deny call for Either return type
- chore: pin tollbooth-dpyc>=0.5.0

## [0.7.0] — 2026-04-12

- remove Horizon OAuth — sessions keyed by npub, no fallback code

## [0.6.36] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.9 — credential validator fix

## [0.6.35] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.8 — ncred fix, courier diagnostics

## [0.6.34] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.6
- Add credential_validator: validates btcpay + client_id + client_secret

## [0.6.33] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.0, rename debit_or_error to debit_or_deny
- split post_tweet into two proper MCP tools
- restore tiered pricing: post_tweet (write) + post_tweet_image (heavy)
- fix: unify post_tweet capability, remove stale post_social_media
- chore: pin tollbooth-dpyc>=0.3.3
- chore: pin tollbooth-dpyc>=0.3.2 — lazy MCP name resolution
- chore: pin tollbooth-dpyc>=0.3.1 — function name MCP stamping
- chore: pin tollbooth-dpyc>=0.3.0 — single tool identity model
- chore: pin tollbooth-dpyc>=0.2.17 for slug namespace filtering
- chore: pin tollbooth-dpyc>=0.2.16
- fix: remove empty Horizon auth helpers section
- chore: pin tollbooth-dpyc>=0.2.14
- chore: pin tollbooth-dpyc>=0.2.13
- feat: UUID-keyed internals — paid_tool and registry use UUID, not short names
- chore: pin tollbooth-dpyc>=0.2.11
- chore: pin tollbooth-dpyc>=0.2.10
- chore: pin tollbooth-dpyc>=0.2.9
- chore: pin tollbooth-dpyc>=0.2.8
- chore: pin tollbooth-dpyc>=0.2.7
- chore: pin tollbooth-dpyc>=0.2.6 for reset_pricing_model
- chore: pin tollbooth-dpyc>=0.2.5
- chore: pin tollbooth-dpyc>=0.2.4 for security fix + legacy UUID fallback
- chore: pin tollbooth-dpyc>=0.2.3 for pricing cache fix
- fix: lint — import ordering, unused import
- fix: lint — remove unused json imports
- feat: UUID-based tool identity — TOOL_COSTS → TOOL_REGISTRY
- fix: store PKCE verifier in vault, not in-memory
- chore: pin tollbooth-dpyc>=0.2.1 — requires PKCE + refresh_access_token
- feat: X OAuth2 Authorization Code + PKCE — replace OAuth 1.0a entirely
- fix: lint — import order, unused os import, unused restore_detail
- fix: remove legacy env vars and dead FileVault code
- fix: use X Dev Portal field names, separate patron/operator credentials cleanly
- fix: X API app keys in operator vault, no env vars — nsec-only principle
- fix: combine patron access tokens with operator app keys in _ensure_session
- chore: pin tollbooth-dpyc>=0.2.0 — clean Neon schema isolation
- chore: pin tollbooth-dpyc>=0.1.173 for onboarding late-attach fix
- chore: pin tollbooth-dpyc>=0.1.172 for credential vault diagnostics
- fix: clear credential state reporting for humans and agents
- fix: improve vault_bootstrapping diagnostics, validate credential fields
- chore: pin tollbooth-dpyc>=0.1.171 — don't cache empty ledgers on cold start
- fix: cold start bugs — patron-facing guidance, remove activate_session, pin >=0.1.170
- chore: pin tollbooth-dpyc>=0.1.169 for session_status lifecycle
- feat: use wheel's themed infographic, delete local copy, pin >=0.1.167
- fix: DRY cleanup — remove redundant health(), fix operator_id → npub
- fix: add onboarding status methods and catalog entries to actor
- chore: pin tollbooth-dpyc>=0.1.165 for demurrage constraint rename
- chore: pin tollbooth-dpyc>=0.1.164 for tranche_expiration constraint
- chore: pin tollbooth-dpyc>=0.1.163 for authority_client npub fix
- chore: pin tollbooth-dpyc>=0.1.162 for patron onboarding status
- fix: pin tollbooth-dpyc>=0.1.161
- chore: pin tollbooth-dpyc>=0.1.160
- fix: lifecycle-aware session guidance for all patron-facing states
- fix: .fastmcp.yaml must declare TOLLBOOTH_NOSTR_OPERATOR_NSEC for bootstrap

## [0.6.31] — 2026-03-29

- chore: pin tollbooth-dpyc>=0.1.159, bump to v0.6.31
- refactor: adopt SessionCache from tollbooth wheel
- refactor: delegate boilerplate to runtime, add Neon vault persistence, annotate npub
- chore: bump tollbooth-dpyc to >=0.1.155
- refactor: strip fastmcp.json to nsec-only
- chore: bump tollbooth-dpyc to >=0.1.152
- chore: require Python >=3.12 (matches Horizon)
- chore: bump tollbooth-dpyc to >=0.1.150
- chore: bump tollbooth-dpyc to >=0.1.147
- chore: bump tollbooth-dpyc to >=0.1.144
- chore: bump tollbooth-dpyc to >=0.1.143
- chore: bump tollbooth-dpyc to >=0.1.138
- chore: bump tollbooth-dpyc to >=0.1.137
- chore: bump tollbooth-dpyc to >=0.1.136
- chore: bump tollbooth-dpyc to >=0.1.135
- chore: bump tollbooth-dpyc to >=0.1.134
- chore: bump tollbooth-dpyc to >=0.1.132
- chore: bump tollbooth-dpyc to >=0.1.131
- chore: bump tollbooth-dpyc to >=0.1.128
- chore: bump tollbooth-dpyc to >=0.1.127
- refactor: dual credential templates, nsec-only Settings
- refactor: npub required in tool descriptions + dead code cleanup
- feat: credential field descriptions for user guidance
- chore: bump tollbooth-dpyc to >=0.1.109
- feat: restore operator-specific Secure Courier greeting
- fix: relax catalog count assertions — catalog evolves with wheel
- fix: ignore N806 (MockClient naming convention in tests)
- fix: ruff auto-fix import sorting + unused imports
- fix: remove unused OperatorProtocol import + ruff lint config
- fix: lint cleanup — unused imports + ignore E501
- feat: add CI workflow + clean up tests for OperatorRuntime
- chore: bump tollbooth-dpyc to >=0.1.108 (infographic restored)
- chore: bump tollbooth-dpyc to >=0.1.107
- refactor: use OperatorRuntime + register_standard_tools
- refactor: npub is required on all credit tools — no session cache
- refactor: _ensure_dpyc_session accepts explicit npub override

## [0.6.30] — 2026-03-22

- chore: bump version to 0.6.30 for release
- chore: bump tollbooth-dpyc to >=0.1.100 (notarization catalog + remove get_tax_rate)

## [0.6.29] — 2026-03-22

- chore: bump tollbooth-dpyc to >=0.1.98 (cache migration fix)
- chore: bump tollbooth-dpyc to >=0.1.97 (tranche TTL expiry)
- chore: bump tollbooth-dpyc to >=0.1.96 for pricing model bridge
- chore: bump tollbooth-dpyc to >=0.1.95 for certify_credits rename
- refactor: rename certifier.certify() to certify_credits()
- chore: bump tollbooth-dpyc to >=0.1.94 for rollback tranche expiry
- chore: nudge deploy for tollbooth-dpyc v0.1.93 PyPI release
- chore: bump tollbooth-dpyc to >=0.1.93
- chore: add fastmcp.json for Horizon deployment config
- chore: nudge deploy for tollbooth-dpyc v0.1.92 release
- Merge pull request #58 from lonniev/chore/bump-tollbooth-0.1.92
- chore: bump tollbooth-dpyc to >=0.1.92 for ACL support
- fix: extract operator_proof from model_json instead of separate tool arg (#57)
- feat: wire operator catalog conformance check at startup, bump to 0.6.29

## [0.6.28] — 2026-03-14

- chore: bump tollbooth-dpyc to >=0.1.91
- feat: gate set_pricing_model to operator-only (Step 0C)
- feat: wire pricing CRUD tools for operator self-service (#56)
- chore: bump tollbooth-dpyc to >=0.1.83 (#55)

## [0.6.27] — 2026-03-09

- chore: bump tollbooth-dpyc to >=0.1.82, version 0.6.27 (#54)
- chore: bump tollbooth-dpyc to >=0.1.81, version 0.6.26 (#53)

## [0.6.25] — 2026-03-08

- chore: bump version to 0.6.25
- Merge pull request #52 from lonniev/refactor/lookup-cache-path
- refactor: remove redundant dpyc_registry_url config

## [0.6.24] — 2026-03-07

- chore: bump version to 0.6.24
- docs: add instructions block + clarify patron npub in tool docstrings (#51)

## [0.6.23] — 2026-03-07

- Merge pull request #50 from lonniev/feat/invoice-dm-delivery
- feat: wire invoice DM delivery via Secure Courier
- chore: bump version to 0.6.22 (#49)

## [0.6.22] — 2026-03-07

- feat: add EXPIRES column to account statement infographic (#48)

## [0.6.21] — 2026-03-07

- fix: remove legacy royalty payout config and params (#47)
- chore: bump to v0.6.20 for clean deploy (native Twitter media for banners)
- fix: upload banner PNG as native Twitter media instead of PostImg
- fix: use correct PostImg upload endpoint with token
- fix: follow redirects on PostImg upload (301 fix)
- fix: switch PostImg to official API endpoint
- fix: replace svglib+reportlab with PyMuPDF for banner SVG→PNG
- fix: pin svglib<1.6.0 to avoid pycairo C dep on FastMCP Cloud
- chore: force redeploy for v0.6.14 (svglib+reportlab)

## [0.6.14] — 2026-03-06

- Merge pull request #46 from lonniev/fix/svglib-renderer
- fix: replace Playwright with svglib+reportlab for banner SVG→PNG

## [0.6.13] — 2026-03-06

- Merge pull request #45 from lonniev/fix/playwright-renderer
- fix: replace cairosvg with Playwright for banner rendering

## [0.6.12] — 2026-03-06

- Merge pull request #44 from lonniev/fix/banner-svg-only
- fix: simplify banner to SVG-only, make cairosvg a required dep

## [0.6.11] — 2026-03-06

- Merge pull request #43 from lonniev/feat/banner-postimg
- chore: bump version to 0.6.11
- feat: add banner_svg_or_png to post_tweet via PostImages upload

## [0.6.10] — 2026-03-06

- chore: bump version to 0.6.10, pin tollbooth-dpyc>=0.1.76
- fix: resolve 22 pre-existing test failures across 4 test files (#42)
- Merge pull request #41 from lonniev/feat/constraint-gate
- feat: wire ConstraintGate into debit flow (opt-in, off by default)
- chore: update README for current architecture (#40)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.75
- chore: pin tollbooth-dpyc>=0.1.75 + surge pricing constraint (#39)
- Merge pull request #38 from lonniev/chore/ecosystem-links
- chore: pin tollbooth-dpyc>=0.1.74 for ECOSYSTEM_LINKS
- chore: add ecosystem_links to service_status response

## [0.6.9] — 2026-03-04

- Merge pull request #37 from lonniev/fix/post-tweet-cost
- fix: set post_tweet cost to 5 api_sats, post_tweet_image to 10
- Merge pull request #36 from lonniev/chore/pin-073
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.73
- Merge pull request #35 from lonniev/feat/pin-trademark
- chore: pin tollbooth-dpyc>=0.1.72 + trademark notices
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.70
- feat: auto-restore DPYC identity from vault on cold start (#34)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.66

## [0.6.8] — 2026-03-03

- Merge pull request #33 from lonniev/feat/auto-certify-purchase
- feat: auto-certify purchase_credits via server-to-server OAuth

## [0.6.7] — 2026-03-03

- Merge pull request #32 from lonniev/feat/slug-prefixing
- feat: slug-prefix all MCP tools with "excalibur_" to avoid name collisions
- feat: ExcaliburOperator protocol conformance (#31)
- Merge pull request #30 from lonniev/feat/dynamic-relay-negotiation
- feat: dynamic relay negotiation + bump tollbooth-dpyc to >=0.1.62
- Merge pull request #29 from lonniev/chore/bump-tollbooth-dpyc-0.1.57
- chore: bump tollbooth-dpyc to >=0.1.57
- chore: bump tollbooth-dpyc to >=0.1.53 (#28)
- Merge pull request #27 from lonniev/chore/bump-tollbooth-dpyc-0.1.52
- chore: bump tollbooth-dpyc to >=0.1.52

## [0.6.5] — 2026-03-01

- chore: force redeploy after NSEC-only identity migration
- Merge pull request #26 from lonniev/feat/nsec-only-registry-resolution
- NSEC-only registry resolution: derive authority npub at runtime (v0.6.5)

## [0.6.4] — 2026-03-01

- Merge pull request #25 from lonniev/feat/courier-greeting
- Resolve merge conflict, bump to v0.6.4
- Pass operator greeting to Secure Courier open_channel
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix) (#24)
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix)

## [0.6.3] — 2026-02-28

- Bump tollbooth-dpyc to >=0.1.48 (NIP-44v2 cipher fix) (#23)

## [0.6.2] — 2026-02-28

- Merge pull request #22 from lonniev/refactor/dry-version
- DRY version: read from importlib.metadata, bump to 0.6.2

## [0.6.1] — 2026-02-28

- Fix __init__.py version to match pyproject.toml (0.6.1)
- Bump version to 0.6.1
- Force redeploy to FastMCP Cloud
- Trigger redeploy — tollbooth-dpyc 0.1.45 now on PyPI
- Remove unused authlib dep, bump tollbooth-dpyc to >=0.1.45 (#21)
- Merge pull request #20 from lonniev/feat/readme
- Add comprehensive README with Secure Courier and tool documentation
- Bridge Secure Courier credentials to passphrase vault (#19)
- Bump tollbooth-dpyc minimum to >=0.1.44 (bare-key repair) (#18)
- Bump tollbooth-dpyc minimum to >=0.1.43 (lenient JSON parsing) (#17)
- Bump tollbooth-dpyc minimum to >=0.1.42 (smart-quote sanitization) (#16)

## [0.6.0] — 2026-02-27

- Add service_status tool + bump tollbooth-dpyc to >=0.1.41 (#15)

## [0.5.0] — 2026-02-27

- Release 0.5.0

## [0.4.2] — 2026-03-09

- chore: bump tollbooth-dpyc to >=0.1.82, version 0.6.27 (#54)
- chore: bump tollbooth-dpyc to >=0.1.81, version 0.6.26 (#53)
- chore: bump version to 0.6.25
- Merge pull request #52 from lonniev/refactor/lookup-cache-path
- refactor: remove redundant dpyc_registry_url config
- chore: bump version to 0.6.24
- docs: add instructions block + clarify patron npub in tool docstrings (#51)
- Merge pull request #50 from lonniev/feat/invoice-dm-delivery
- feat: wire invoice DM delivery via Secure Courier
- chore: bump version to 0.6.22 (#49)
- feat: add EXPIRES column to account statement infographic (#48)
- fix: remove legacy royalty payout config and params (#47)
- chore: bump to v0.6.20 for clean deploy (native Twitter media for banners)
- fix: upload banner PNG as native Twitter media instead of PostImg
- fix: use correct PostImg upload endpoint with token
- fix: follow redirects on PostImg upload (301 fix)
- fix: switch PostImg to official API endpoint
- fix: replace svglib+reportlab with PyMuPDF for banner SVG→PNG
- fix: pin svglib<1.6.0 to avoid pycairo C dep on FastMCP Cloud
- chore: force redeploy for v0.6.14 (svglib+reportlab)
- Merge pull request #46 from lonniev/fix/svglib-renderer
- fix: replace Playwright with svglib+reportlab for banner SVG→PNG
- Merge pull request #45 from lonniev/fix/playwright-renderer
- fix: replace cairosvg with Playwright for banner rendering
- Merge pull request #44 from lonniev/fix/banner-svg-only
- fix: simplify banner to SVG-only, make cairosvg a required dep
- Merge pull request #43 from lonniev/feat/banner-postimg
- chore: bump version to 0.6.11
- feat: add banner_svg_or_png to post_tweet via PostImages upload
- chore: bump version to 0.6.10, pin tollbooth-dpyc>=0.1.76
- fix: resolve 22 pre-existing test failures across 4 test files (#42)
- Merge pull request #41 from lonniev/feat/constraint-gate
- feat: wire ConstraintGate into debit flow (opt-in, off by default)
- chore: update README for current architecture (#40)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.75
- chore: pin tollbooth-dpyc>=0.1.75 + surge pricing constraint (#39)
- Merge pull request #38 from lonniev/chore/ecosystem-links
- chore: pin tollbooth-dpyc>=0.1.74 for ECOSYSTEM_LINKS
- chore: add ecosystem_links to service_status response
- Merge pull request #37 from lonniev/fix/post-tweet-cost
- fix: set post_tweet cost to 5 api_sats, post_tweet_image to 10
- Merge pull request #36 from lonniev/chore/pin-073
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.73
- Merge pull request #35 from lonniev/feat/pin-trademark
- chore: pin tollbooth-dpyc>=0.1.72 + trademark notices
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.70
- feat: auto-restore DPYC identity from vault on cold start (#34)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.66
- Merge pull request #33 from lonniev/feat/auto-certify-purchase
- feat: auto-certify purchase_credits via server-to-server OAuth
- Merge pull request #32 from lonniev/feat/slug-prefixing
- feat: slug-prefix all MCP tools with "excalibur_" to avoid name collisions
- feat: ExcaliburOperator protocol conformance (#31)
- Merge pull request #30 from lonniev/feat/dynamic-relay-negotiation
- feat: dynamic relay negotiation + bump tollbooth-dpyc to >=0.1.62
- Merge pull request #29 from lonniev/chore/bump-tollbooth-dpyc-0.1.57
- chore: bump tollbooth-dpyc to >=0.1.57
- chore: bump tollbooth-dpyc to >=0.1.53 (#28)
- Merge pull request #27 from lonniev/chore/bump-tollbooth-dpyc-0.1.52
- chore: bump tollbooth-dpyc to >=0.1.52
- chore: force redeploy after NSEC-only identity migration
- Merge pull request #26 from lonniev/feat/nsec-only-registry-resolution
- NSEC-only registry resolution: derive authority npub at runtime (v0.6.5)
- Merge pull request #25 from lonniev/feat/courier-greeting
- Resolve merge conflict, bump to v0.6.4
- Pass operator greeting to Secure Courier open_channel
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix) (#24)
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix)
- Bump tollbooth-dpyc to >=0.1.48 (NIP-44v2 cipher fix) (#23)
- Merge pull request #22 from lonniev/refactor/dry-version
- DRY version: read from importlib.metadata, bump to 0.6.2
- Fix __init__.py version to match pyproject.toml (0.6.1)
- Bump version to 0.6.1
- Force redeploy to FastMCP Cloud
- Trigger redeploy — tollbooth-dpyc 0.1.45 now on PyPI
- Remove unused authlib dep, bump tollbooth-dpyc to >=0.1.45 (#21)
- Merge pull request #20 from lonniev/feat/readme
- Add comprehensive README with Secure Courier and tool documentation
- Bridge Secure Courier credentials to passphrase vault (#19)
- Bump tollbooth-dpyc minimum to >=0.1.44 (bare-key repair) (#18)
- Bump tollbooth-dpyc minimum to >=0.1.43 (lenient JSON parsing) (#17)
- Bump tollbooth-dpyc minimum to >=0.1.42 (smart-quote sanitization) (#16)
- Add service_status tool + bump tollbooth-dpyc to >=0.1.41 (#15)
- Add runtime version reporting to health endpoint (#14)
- Bump tollbooth-dpyc minimum to >=0.1.40 (dual-protocol DM + timestamp fix) (#13)
- Bump tollbooth-dpyc minimum to >=0.1.39 (base64 padding fix) (#12)
- Add Secure Courier onboarding guidance to tool metadata and error responses (#11)
- Bump tollbooth-dpyc minimum to >=0.1.38 (NIP-17 gift-wrapped DMs) (#10)
- Bump tollbooth-dpyc minimum to >=0.1.37 (ConstraintGate middleware) (#9)
- Refactor Secure Courier to use shared SecureCourierService (#8)
- Merge pull request #7 from lonniev/feat/infographic-port
- Bump tollbooth-dpyc minimum to >=0.1.34 (relay diagnostics + DM notifications)
- Add account_statement_infographic tool with Excalibur-branded SVG
- Merge pull request #6 from lonniev/feat/unified-onboarding
- Bump tollbooth-dpyc minimum to >=0.1.33 (conversational DM + NIP-17)
- Establish DPYC identity and seed balance in Secure Courier receive
- Merge pull request #5 from lonniev/feat/welcome-dm-profile
- Add welcome DM flip and Nostr profile publishing
- Add PNG version of avatar for Nostr profile compatibility
- Add eXcalibur MCP avatar for Nostr operator profile
- chore: empty commit to force Horizon redeploy
- Merge pull request #3 from lonniev/fix/license-spelling
- Merge pull request #4 from lonniev/fix/courier-template-v2
- Reduce X credential template to 2 fields (access_token pair only)
- Fix last excaliber → excalibur typo in LICENSE
- chore: empty commit to force Horizon redeploy
- Wire Secure Courier tools for out-of-band X API credential delivery (#2)
- chore: empty commit to force Horizon redeploy
- Support long-form posts and optional image attachments
- Rename excaliber → excalibur across package and codebase
- Migrate to Nostr Schnorr certificate verification
- Enforce credit gating in all modes; populate .env.example
- Add Tollbooth credit gating and monetization infrastructure
- Add multi-tenant credential vault with per-user X API OAuth
- Trigger Horizon redeploy
- Add FastMCP Cloud (Horizon) deployment config
- Merge pull request #1 from lonniev/feat/post-tweet
- Fix OAuth 1.0a signing: manual header instead of authlib
- Add post_tweet tool with markdown → Unicode formatting
- Initial project scaffolding for eXcaliber-mcp

