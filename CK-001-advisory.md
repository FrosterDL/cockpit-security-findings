# Advisory paste — CK-001 (held packet, not yet submitted anywhere)

**Title:** Cockpit CMS: Buckets file-storage API has no authorization check — any authenticated user can list, upload, rename and delete files in any bucket (persists in 2.14.x; cf. CVE-2026-57855 for < 2.14.0)

**Affected product:** Cockpit CMS (cockpit-hq/cockpit), Packagist `cockpit-hq/cockpit`

**Affected versions:** Confirmed on 2.14.1 and on main @ 47254975 (2.14.1-6, 2026-11-14). The controller contains no authorization check in the 2.14.0 tag, the 2.14.1 tag, or current main. Versions < 2.14.0 are covered by CVE-2026-57855; this report concerns the current release line, where the issue was understood to be fixed.

**Severity:** High (provisional)

**CWE:** CWE-862

**Patched version:** None

## Summary

The Buckets file-storage endpoint (`POST /system/buckets/api/{bucket}`, `System\Controller\Buckets::api()`) checks only that the caller has an authenticated session and a valid CSRF token. It never checks any role or permission. Any authenticated user — including custom roles whose only permissions are reading content — can list, upload, create folders in, rename and delete files in any bucket, and can create new buckets by naming them. Uploaded files are stored under the web-served `storage/uploads/buckets/` directory and are publicly fetchable.

## Steps to reproduce (own local installation, 2.14.1)

1. Create two custom roles: `editor` (permissions: `content/posts/read`, `content/posts/create`, `content/posts/update`) and `apireader` (permission: `content/posts/read`). Create one user per role and sign in as the `editor` user.
2. `POST /system/buckets/api/huntbucket` with `cmd=createfolder`, `name=test` → `{"success":true}`.
3. `POST /system/buckets/api/huntbucket` with `cmd=upload` and a `files[]` text file → `{"uploaded":["editor1.txt"],"failed":[]}`.
4. `cmd=rename` and `cmd=removefiles` on that file → both `{"success":true}`.
5. Repeat all steps signed in as the read-only `apireader` user → identical results.
6. Upload a file as `editor`, then fetch `GET /storage/uploads/buckets/huntbucket/<file>` without any credentials → HTTP 200 with the file content.

Control: the same requests without a session are rejected (login required); the issue is the missing authorization, not missing authentication.

## Impact

Any authenticated account, regardless of role, gains full control over the bucket file storage: publishing arbitrary allowed-type files (images, documents, archives, scripts such as .js/.json/.xml, sanitized SVG) to the site's public uploads area, enumerating bucket contents, and renaming or deleting files that administrators manage through buckets. Upload filters block executable/HTML file types and path traversal out of the bucket root, so no code execution was demonstrated through this endpoint; impact is unauthorized file hosting, disclosure of bucket contents, and loss of integrity/availability of bucket-managed files.

## Root cause

`modules/System/Controller/Buckets.php`, method `api()`: after CSRF validation it dispatches the requested command (`ls`, `upload`, `createfolder`, `rename`, `removefiles`) without any ACL check (`isAllowed()` / `isSuperAdmin()`), unlike the other System controllers. The 2.14.0 changes to this controller hardened file-type and path handling but did not add authorization.

## Vendor communication status

Not yet reported through any other channel; no CVE assigned for the current release line.
