# Cockpit CMS — security findings

Findings in **Cockpit CMS** (GitHub: [Cockpit-HQ/Cockpit](https://github.com/Cockpit-HQ/Cockpit),
v2 line), confirmed on release **2.14.1** and main at
`47254975a0296ea3ce264dd5692142b7f68dea59` (2026-11-14), PHP 8.3.6 with SQLite
storage, on the reporter's own local installation.

Each finding was reproduced against that local installation with control vs
attack runs and persisted-state verification. Full methodology, controls and
results: [EVIDENCE.md](EVIDENCE.md).

Finder: FrosterDL

## Findings

1. **CK-001 — Missing authorization in the Buckets file-storage API**
   (High, provisional)
   [CK-001-advisory.md](CK-001-advisory.md) · CWE-862 ·
   harness: [CK-001-harness.py](CK-001-harness.py) (exit 0).
   Same component/class as CVE-2026-57855 (fixed in 2.14.0 for earlier
   versions); the 2.14.0 fix hardened file types/paths only — authorization
   is still absent in the current release, as stated in the advisory.

2. **CK-002 — GraphQL `saveContentItem` bypasses the publish permission**
   (Moderate, provisional)
   [CK-002-advisory.md](CK-002-advisory.md) · CWE-862 ·
   harness: [CK-002-harness.py](CK-002-harness.py) (exit 0)

3. **CK-003 — Unpublished singleton content disclosed by the generic
   GraphQL `content` query** (Low, provisional)
   [CK-003-advisory.md](CK-003-advisory.md) · CWE-862/200 ·
   harness: [CK-003-harness.py](CK-003-harness.py) (exit 0)

4. **CK-004 — Deactivated user accounts keep working personal API keys**
   (Low, provisional)
   [CK-004-advisory.md](CK-004-advisory.md) · CWE-613/862 ·
   harness: [CK-004-harness.py](CK-004-harness.py) (exit 0)

The upstream repository has private vulnerability reporting disabled; its
SECURITY.md names email only (security@getcockpit.com), with scope limited
to the reporter's own local installation. The vendor has not been contacted
yet. These findings are disclosed here and are being submitted to VulDB with CVE
requests; no CVE has been assigned and no other CNA has been approached.
