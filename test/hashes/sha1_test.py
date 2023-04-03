import json, os.path, time

from cryptonita import B
from cryptonita.toys.hashes.sha1 import sha1

path = os.path.abspath(os.path.dirname(__file__))
path = os.path.join(path, '../ds/test_vectors/sha_testvectors.json')

cases = json.load(open(path, 'rt'))[1]
test_vectors = [(B(d['message']['data']), int(d['message']['count']), B(d['SHA-1'])) for d in cases]

for ix, (d, c, expected) in enumerate(test_vectors[:-1]):
    print(f"Test {ix} ({len(d) * c} bytes)...")
    msg = bytes(d * c)

    begin = time.time()
    obtained = sha1(msg)
    elapsed = time.time() - begin
    print(f"Test {ix} ({len(d) * c} bytes) completed in {elapsed} secs.")

    obtained = B(obtained)
    if obtained == expected:
        print(f"Result? OK")
    else:
        print(f"Result? FAIL:\nobtained: {obtained}\nexpected: {expected}")
