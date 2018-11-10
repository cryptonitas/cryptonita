from cryptonita.mixins import MutableSequenceMixin, SequenceStatsMixin

'''
>>> from cryptonita import B
'''

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
