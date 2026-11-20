# Advisory paste — CK-004 (held packet, not yet submitted anywhere)

**Title:** Cockpit CMS: personal API keys of deactivated user accounts remain valid

**Affected product:** Cockpit CMS (cockpit-hq/cockpit), Packagist `cockpit-hq/cockpit`

**Affected versions:** Confirmed on 2.14.1 and main @ 47254975; the authentication code is identical in 2.14.0, 2.14.1 and current main.

**Severity:** Low (provisional)

**CWE:** CWE-613

**Patched version:** None

## Summary

A Cockpit user account can have a personal API key (tokens starting with `USR-`) that authenticates API requests with that user's role. Deactivating the account (`active = false`) blocks interactive login, but the personal API key continues to authenticate API requests with the account's full role scope — including content creation/modification for write-capable roles. The API authentication code looks up the user by API key without checking the account's `active` flag, so deactivation does not revoke API access.

## Steps to reproduce (own local installation, 2.14.1)

1. Create a user with a write-capable role (e.g. content create/update) and set a personal API key on the account.
2. Verify the key works: `GET /api/content/items/posts` with header `api-key: USR-...` → HTTP 200.
3. As administrator, deactivate the user (`active = false`). Verify in the database that the flag is stored.
4. Control: interactive login with the user's credentials → rejected.
5. Attack: repeat the API request with the same `USR-` key → HTTP 200; `POST /api/content/item/posts` with the key creates a new item attributed to the deactivated user (`_cby` = their user id).

## Impact

Account deactivation — the standard response to offboarding or compromise — silently fails to revoke API access. A deactivated user, or anyone who obtained their personal API key, keeps read/write API access at the account's role level until an administrator also manually clears the key field.

## Root cause

`modules/App/api.php` (`/api/*` binding): the `USR-` token branch loads the user with `findOne('system/users', ['apiKey' => $token])` and never verifies `$user['active']`.

## Vendor communication status

Not yet reported through any other channel; no CVE assigned.
