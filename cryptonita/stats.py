import collections
import itertools as itools

import math
def _py_entropy(pk, qk=None, base=None):
    '''
        >>> from cryptonita.stats import _py_entropy

        Input normalized
        >>> _py_entropy([0.3, 0.5, 0.2])
        1.0296530140645<...>

        Input not normalized
        >>> _py_entropy([1.3, 2.5, 3.2])
        1.0382125826451<...>

        Different log base (e by default)
        >>> _py_entropy([1.3, 2.5, 3.2], base=7)
        0.5335357252487<...>

        Two inputs (Kullback-Leibler divergence)
        >>> _py_entropy([0.3, 0.5, 0.2], [0.1, 0.1, 0.8])
        0.8570437705935<...>

        Two inputs: not normalized - normalized
        >>> _py_entropy([1.3, 2.5, 3.2], [0.1, 0.1, 0.8])
        0.3137706627238<...>

        Two inputs: normalized - not normalized
        >>> _py_entropy([0.3, 0.5, 0.2], [1.1, 2.1, 3.8])
        0.24969519533828<...>

        Two inputs: different base.
        >>> _py_entropy([1.3, 2.5, 3.2], [0.1, 0.1, 0.8], base=7)
        0.1612462234580<...>

    '''
    log = math.log
    if base == None:
        base = math.e

    if qk == None:
        np = sum(pk)
        return log(np, base) - sum((p * log(p, base)) for p in pk) / np
    else:
        np = sum(pk)
        nq = sum(qk)
        return - log(np/nq, base) + sum((p * log(p/q, base)) for p, q in zip(pk, qk)) / np

try:
    from scipy.stats import entropy
except ImportError:
    entropy = _py_entropy


class SequenceStatsMixin:
    def freq(self):
        return collections.Counter(self)

    def most_common(self, n):
        elems, _ = zip(*self.freq().most_common(n))
        return elems

    def entropy(self, qk=None, base=None):
        freq = list(self.freq().values())
        return entropy(freq, qk, base)

    def iduplicates(self, distance, idx_of='second'):
        r'''Return the index of each duplicates or repeated item.

            An item is considered duplicated if another item is
            the same *and* it is <distance> items of distance.

            <distance> equal to 0 means "two consecutive items"

                >>> from cryptonita.bytestring import B

                >>> blocks = B('AABBAACCCCDDAADDAA').nblocks(2)
                >>> list(blocks)
                ['AA', 'BB', 'AA', 'CC', 'CC', 'DD', 'AA', 'DD', 'AA']

                >>> # the CCs
                >>> list(blocks.iduplicates(distance=0))
                [4]

                >>> # the first 2 and last 2 AAs and the DDs
                >>> list(blocks.iduplicates(distance=1))
                [2, 7, 8]

                >>> # the first 2 AAs with the last 2 AAs
                >>> list(blocks.iduplicates(distance=5))
                [6, 8]

            By default returns the indexes of the "second" item, the
            duplicated.

            But it is possible to return the index of the first:

                >>> list(blocks.iduplicates(distance=5, idx_of='first'))
                [0, 2]

            Or even of both (notice how the indexes are mixed):

                >>> list(blocks.iduplicates(distance=5, idx_of='both'))
                [0, 6, 2, 8]

        '''
        assert idx_of in ('both', 'first', 'second')

        # consecutive items if distance is 0
        # 1 item between if distance is 1, ...
        left, right = itools.tee(self)
        right = itools.islice(right, 1+distance, None)

        # ``left`` is longer than ``right`` but it is ok: we want to drop
        # the last items from ``left`` and zip() will do that for us
        pairs = zip(left, right)

        idx = 0
        for a, b in pairs:
            if a == b:
                if idx_of in ('first', 'both'):
                    yield idx
                if idx_of in ('second', 'both'):
                    yield idx+distance+1
            idx += 1

    def has_duplicates(self, distance):
        return next(self.iduplicates(distance), None) != None
