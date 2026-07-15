# Changelog

## v2.4.0 — 2026-07-15

Inventory scanner compatibility fix, a few Completionist bugs squashed, and WFM rate limiting corrections.

🔧 Bug Fixes
Fixed the inventory scanner failing entirely for some accounts. The FULL_ACCOUNT blob in memory has a different field order per account — on affected accounts the scanner's start-marker search landed inside a nested JSON object, producing an invalid fragment that was silently discarded. The scanner now buffers preceding memory regions and correctly locates the true blob opening regardless of field order.

Fixed the Helminth subsumed badge (green "H") not appearing in the Completionist Research Labs tab. Subsumed warframes with qty=0 were excluded from the inventory map so the badge condition always evaluated against undefined.

Fixed combined-weapon components being incorrectly marked as unowned. Weapons that are ingredients for another weapon (e.g. Kohmak → Twin Kohmak) were being redirected to their combined parent, causing the base weapon to show "—" even when owned. The redirect now only applies to warframe/archwing component parts.

✨ New — Auction Rate Limiter
Warframe.market enforces a separate limit of 10 requests per minute on contract endpoints (rivens, liches, sisters). FrameForge now applies this limit correctly in addition to the existing 3 req/sec general limiter, preventing 429 errors when browsing or managing riven auctions.

📌 Note
The "Sisters" tab in Market Helper has been renamed to "Variants" to better reflect the full scope it will cover (Sisters of Parvos, Liches, Tenet and Kuva weapons).

---

## v2.3.0

Previous release.
