import base64
from cryptonita.mixins import SequenceMixin, ByteStatsMixin, SequenceStatsMixin

'''
>>> from cryptonita import B
>>> from cryptonita.immutable_bytestring import ImmutableByteString
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

    def join(self, *others):
        raise NotImplementedError("Not yet")
        return B(bytes.join(self, *others))

