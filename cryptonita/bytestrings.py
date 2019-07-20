from cryptonita.mixins import (
        SequenceMixin,
        MutableSequenceMixin,
        ByteStatsMixin,
        SequenceStatsMixin
        )

import numpy as np

'''
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.bytestrings import MutableByteString, ImmutableByteString
'''

class ImmutableByteString(SequenceMixin, ByteStatsMixin, SequenceStatsMixin, bytes):
    ''' Enhanced version of a immutable byte string.

            >>> s = B(b'ABA')
            >>> isinstance(s, bytes) and type(s) != bytes
            True

        This also supports some basic statistics:

            >>> s.freq()
            Counter({65: 2, 66: 1})

            >>> s.most_common(n=1)
            (65,)

            >>> s.entropy()
            0.6365141682948<...>

            >>> list(s.iduplicates(distance=1, idx_of='first'))
            [0]

        For convenience, iterating a ImmutableByteString yields integers
        like 'bytes'

            >>> list(s)
            [65, 66, 65]

            >>> s[0]
            65

        For this reason a byte string of just 1 byte can be compared
        with an integer and both a byte and an integer can be used as keys:

            >>> one_byte = B(b'A')
            >>> (one_byte == 65), (hash(one_byte) == hash(65))
            (True, True)

            >>> isinstance(one_byte, int)
            False

            >>> one_byte in s.freq()
            True
    '''
    __slots__ = ()
    def __repr__(self):
        return super().__repr__()[1:]

    def tobytes(self):
        return self

    def __hash__(self):
        if len(self) == 1:
            return hash(self[0])
        return super().__hash__()

    def __eq__(self, other):
        if isinstance(other, int) and len(self) == 1:
            return other == self[0]
        return super().__eq__(other)

    def toarray(self):
        return np.array(tuple(self))

    def fhex(self, n=8):
        return super().hex()[:n]

class MutableByteString(MutableSequenceMixin, bytearray):
    ''' Enhanced version of a mutable byte string.

            >>> s = B(b'ABA', mutable=True)
            >>> isinstance(s, bytearray) and type(s) != bytearray
            True
    '''
    __slots__ = ()

    def __repr__(self):
        return super().__repr__()[11:-1]

    def tobytes(self):
        return bytes(self)

    def toarray(self):
        return np.array(tuple(self))
