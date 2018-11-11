from cryptonita.mixins import (
        SequenceMixin,
        MutableSequenceMixin,
        ByteStatsMixin,
        SequenceStatsMixin
        )

'''
>>> from cryptonita import B
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
    '''
    __slots__ = ()
    def __repr__(self):
        return super().__repr__()[1:]

    def tobytes(self):
        return self


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
