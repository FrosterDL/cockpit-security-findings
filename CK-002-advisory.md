# Advisory paste — CK-002 (held packet, not yet submitted anywhere)

**Title:** Cockpit CMS: GraphQL saveContentItem mutation does not enforce the publish permission — users with update-only access can publish and unpublish content

**Affected product:** Cockpit CMS (cockpit-hq/cockpit), Packagist `cockpit-hq/cockpit`

**Affected versions:** Confirmed on 2.14.1 and main @ 47254975; `modules/Content/graphql/content.php` is identical in 2.14.0, 2.14.1 and current main, and the defective code was introduced with the mutation itself (commit 7259ab06), so all 2.x versions shipping the GraphQL `saveContentItem` mutation are expected to be affected.

**Severity:** Moderate (provisional)

**CWE:** CWE-862

**Patched version:** None

## Summary

Cockpit separates the content permissions `create`, `update` and `publish`: a role may be allowed to edit items but not to change their publication state (`_state`). The REST API enforces this by removing `_state` from update payloads when the caller lacks the `publish` permission. The GraphQL `saveContentItem` mutation contains the same check, but it unsets `_state` on the wrong variable (`$item`, which is undefined at that point, instead of `$data`), so the check has no effect and the supplied `_state` is persisted. Update-only users can publish drafts and unpublish live items via GraphQL.

## Steps to reproduce (own local installation, 2.14.1)

1. Create a role `editor` with permissions `content/posts/read`, `content/posts/create`, `content/posts/update` (no `publish`) and an API key bound to that role. Create a collection `posts` with one published item and one draft (`_state=0`).
2. Control (REST): `POST /api/content/item/posts` with the editor key and body `{"data": {"_id": "<draft-id>", "_state": 1}}` → response and database still show `_state: 0`.
3. Attack (GraphQL): `POST /api/gql` with the editor key and mutation `saveContentItem(model: "posts", data: {_id: "<draft-id>", _state: 1})` → the draft is returned with `_state: 1` and the database record is now published.
4. Repeat with `_state: 0` against the published item → the live item is unpublished in the database.

## Impact

An API credential whose role may edit but not publish content can change the publication state of any item in models it can update: publishing drafts that are pending review (potentially unvetted or embargoed content) and unpublishing live content (availability/integrity of the published site). Create and delete permissions are not affected.

## Root cause

`modules/Content/graphql/content.php`, `saveContentItem` resolver: `unset($item['_state']);` should be `unset($data['_state']);` (as correctly done in `modules/Content/api.php`).

## Vendor communication status

Not yet reported through any other channel; no CVE assigned.
