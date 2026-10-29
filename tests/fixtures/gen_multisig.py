# Verifies tests/fixtures/multisig.json with embit (an unrelated library): each descriptor must parse with a valid
# checksum and derive exactly the recorded addresses. The cosigner keys were made with @scure/bip32.
import json, sys
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
bad = n = 0
for r in json.load(open(sys.argv[1] if len(sys.argv) > 1 else 'tests/fixtures/multisig.json')):
    for dk, b in (('desc0', 0), ('desc1', 1)):
        d = Descriptor.from_string(r[dk])
        for a in r['addrs']:
            if a['b'] != b: continue
            n += 1
            if d.derive(a['i']).address(NETWORKS['main']) != a['addr']: bad += 1; print('MISMATCH', a)
print(n, 'checks,', bad, 'bad'); sys.exit(1 if bad else 0)
