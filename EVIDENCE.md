# Cockpit CMS — Dynamic Testing Evidence

Target: Cockpit 2.14.1 + main @ 47254975, own local install, PHP 8.3.6 built-in server, SQLite.
Method: deep dynamic testing only (PayloadsAllTheThings-informed payload classes + targeted authorization matrices). Every confirmed finding has control vs attack runs and persisted-state verification (SQLite re-read or anonymous re-fetch). Scripts: `ck.py`, `setup_fixtures.py`, `test_api.py`, `test_buckets.py`, `test_graphql.py`, `test_admin_session.py`, `test_assets.py`, `test_usrkeys.py`; per-finding harnesses in `findings/CK-*/harness.py` (all exit 0).

## Confirmed findings

### CK-001 — Buckets API: missing authorization (High, provisional) → findings/CK-001-buckets-missing-authorization/
`System\Controller\Buckets::api()` has no ACL check (0 occurrences of `isAllowed` in 2.14.0 tag, 2.14.1 tag, HEAD). As `editor1` (content-only role) and as `reader1` (read-only role): createfolder/upload/rename/removefiles all succeed on arbitrary buckets; naming a new bucket auto-creates it; an editor-uploaded file was fetched anonymously at `/storage/uploads/buckets/huntbucket/proof.txt` (HTTP 200, exact content). Same component/class as CVE-2026-57855 (< 2.14.0) — the claimed 2.14.0 fix added file-type/path hardening only; authorization is still absent in the current release. Full detail in the finding report.

### CK-002 — GraphQL `saveContentItem` publish-permission bypass (Moderate, provisional) → findings/CK-002-graphql-publish-bypass/
Typo `unset($item['_state'])` (should be `$data`) in `modules/Content/graphql/content.php` makes the publish check a no-op. Editor-role API key (update, no publish): REST control leaves draft `_state=0` in DB; GraphQL mutation sets draft `_state=1` and published item `_state=0`, both verified in `content.sqlite`. `deleteContentItem` control correctly denied.

### CK-003 — Generic GraphQL `content` query leaks unpublished singleton (Low, provisional) → findings/CK-003-graphql-singleton-state-leak/
Singleton `siteconfig` unpublished with marker secret: REST item endpoint → 404; per-model GraphQL → null; generic GraphQL `{ content(model:"siteconfig") }` → full item incl. marker and `_state:0`, with a read-only key that legitimately has read permission on the model. Collections unaffected.

### CK-004 — Deactivated account's personal API key stays valid (Low, provisional) → findings/CK-004-deactivated-user-api-key/
`modules/App/api.php` USR- branch: `findOne('system/users', ['apiKey' => $token])` — no `active` check. After admin deactivated `editor1` (DB-verified `active:false`; session login correctly blocked), the account's `USR-` key still created content (HTTP 200, `_cby` = deactivated user's id). Read access for a deactivated read-only account likewise confirmed.

## Regression battery — prior CVE classes re-tested on 2.14.1/HEAD, all fixes HOLD

- **State-filter bypass (REST + GraphQL):** `filter` with `_state=0`, `$ne`, `$in`, `$or` — published-only results everywhere; draft by ID → 404; multi-model endpoint skips unauthorized models.
- **Aggregation (CVE-2026-6626 / 31891 / 38992):** user `$match` cannot undo the prepended `_state=1` match; `$group` by `_state` shows only state 1; `$lookup`/`$unionWith` → 500 (unsupported), no data; `$func` in items filter → 500, in aggregate → constrained to published set; field-name/sort-key SQL-injection strings (quotes, JSON paths, `SELECT`) → no effect, no draft data.
- **Buckets hardening (CVE-2026-38991 / 38993):** rename to `.php` → `success:false`; `..` in `path`/`paths[]` normalized/contained (no file outside bucket touched); upload of `.html`, `.php`-content `.txt` (x-php MIME) → "File type not allowed"; script SVG → sanitized (script stripped in served bytes).
- **Assets upload:** editor without `assets/upload` → 401. Admin: `.html`/`.php`/`.phtml` rejected; HTML content disguised as `.png` rejected by MIME sniffing; double extension neutralized by renaming; script SVG uploaded but served sanitized.
- **Admin authorization matrix (fresh session per call to avoid CSRF-key rotation artifacts):** editor saving own profile with `role=admin` → role stripped, DB unchanged; editor saving admin's profile → 401; editor creating a user → 401; `/system/api/save`, `/system/users/roles/save`, `/system/spaces/create`, `/system/logs`, `/content/models/save` as editor → 401; collection `updateState`/`remove` did not change DB state for editor (no publish/delete perm); System Utils dangerous actions (`env`, `flushCache`, `testMailer`) are superadmin-gated in code.
- **Auth flows:** password reset and magic-link tokens are JWTs carrying a bcrypt hash of `_id . current-password-hash . _modified` with 15-minute expiry — using one changes `_modified` and the password hash, so tokens are single-use and cannot be transplanted between users; `validate2FA` re-loads the user from the DB and verifies the TOTP against the stored secret (the CVE-2022-2818 pattern does not recur). Session login of a deactivated account is blocked.
- **REST API key scoping:** bogus key → 412; read-only key create/delete → 403; per-user `USR-` keys enforce the owner's role (editor key: create OK, REST publish stripped, delete 403).
- **GraphQL:** `content`/`postsModel` queries force `_state=1` and check read ACL; `deleteContentItem` checks delete permission.

## Parked / not filed (with reasons)

- **Default JWT signing key (`sec-key`).** `bootstrap.php` ships default `'sec-key' => 'c3b40c4c-db44-s5h7-a814-b5931a15e5e1'` ("change me in custom config"); a default install without a custom config uses it — dynamically proven in this instance via the app's own bootstrap: `retrieve('sec-key')` returns the public default and a token signed with it verifies through the app JWT helper. However, every core consumer binds tokens to server-side secrets (reset/magic-link: bcrypt of the current password hash + modified timestamp; CSRF: per-session random key inside the payload check; 2FA: DB-stored TOTP), so **no concrete exploit was demonstrated** with the key alone. Recorded as a hardening observation, not a finding (also: vendor SECURITY.md excludes documented behaviour / issues guardable by following their recommendations).
- **Asset metadata listing** (`/assets/assets`, `/assets/asset`) is available to any authenticated session without an assets permission. Metadata only; the files themselves are publicly served by design. Not filed.
- **Thumbnail endpoint** (`/assets/thumbnail`): traversal-style `src` values returned 404; a valid-image control errored on synthetic test data, so no positive traversal signal was obtained. Not filed.
- **Identi (OIDC SSO) module:** inactive unless an external IdP is configured; not part of a default install. Not tested.
- **Response cache `?rspc=1`**, custom file-based API routes, Spaces multi-tenancy internals, tree models, and content `populate` link expansion: no positive signal in scoped testing / require non-default configuration. Not filed.
- **CVE-2026-34965 (Collections RCE):** targets the v1-style collections endpoint/history (agentejo repo); not present in the v2 code line tested. Not applicable; v2 model-save authorization was tested instead and holds.

## Reproduction

1. `php -S 127.0.0.1:18080 -t ~/workspace/cockpit-hunt/src` (instance already installed; admin `admin` / `AdminPass123!`).
2. `cd ~/workspace/cockpit-hunt/live-repro && python3 setup_fixtures.py` (idempotent-ish fixture creation; roles/users/keys/models/items).
3. Run any `findings/CK-*/harness.py` — prints control vs attack lines and a VERDICT, exit 0 = reproduced.
