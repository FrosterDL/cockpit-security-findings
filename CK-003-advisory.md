# Advisory paste — CK-003 (held packet, not yet submitted anywhere)

**Title:** Cockpit CMS: generic GraphQL content query returns unpublished singleton items

**Affected product:** Cockpit CMS (cockpit-hq/cockpit), Packagist `cockpit-hq/cockpit`

**Affected versions:** Confirmed on 2.14.1 and main @ 47254975; the resolver file is identical in 2.14.0, 2.14.1 and current main.

**Severity:** Low (provisional)

**CWE:** CWE-862, CWE-200

**Patched version:** None

## Summary

For singleton content models, the generic GraphQL query `content(model: "...")` returns the singleton item regardless of its publication state (`_state`). The REST API and the per-model GraphQL query both withhold unpublished singletons; the generic GraphQL query does not check `_state` in its singleton branch. API keys with read permission on a singleton model can therefore retrieve its unpublished (draft) content. Collection models are not affected.

## Steps to reproduce (own local installation, 2.14.1)

1. Create a singleton model (e.g. `siteconfig`) with a text field, save an item with a marker value, then set the item to unpublished (`_state = 0`).
2. Use an API key whose role has `content/siteconfig/read`.
3. Control 1: `GET /api/content/item/siteconfig` → 404 (nothing returned).
4. Control 2: GraphQL `{ siteconfigModel { ... } }` → `null`.
5. Attack: GraphQL `{ content(model: "siteconfig") }` → HTTP 200 with the full unpublished item, including the marker field and `_state: 0`.

## Impact

Holders of read-only API credentials for a singleton model can read its unpublished content — e.g. staged site configuration, announcements or settings that were deliberately taken offline or not yet released — even though every other API path withholds it.

## Root cause

`modules/Content/graphql/content.php`, `content` query resolver, singleton branch returns `$app->module('content')->item($model)` without applying the `_state = 1` restriction that the collection branch and the other API paths enforce.

## Vendor communication status

Not yet reported through any other channel; no CVE assigned.
