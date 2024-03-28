from cryptonita.mixins import (
    SequenceMixin, MutableSequenceMixin, ByteStatsMixin, SequenceStatsMixin
)

from cryptonita.deps import importdep

np = importdep('numpy')

from collections.abc import Iterable, Callable
'''
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.bytestrings import MutableByteString, ImmutableByteString
'''


class ImmutableByteString(
    SequenceMixin, ByteStatsMixin, SequenceStatsMixin, bytes
):
    ''' Enhanced version of an immutable byte string.

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

        For convenience, iterating an ImmutableByteString yields integers
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

    def map(self, table, table2=None, fill=-1, delete=set()):
        ''' Translate the byte string replacing each byte
            by the byte given in <table>, optionally deleting
            bytes from the <delete> set and filling the missing
            ones with <fill>.

            This is an enhanced version of bytes.translate()
            and str.translate().

            The <table> can be a bytes-like sequence of 256
            bytes and the mapping is based on position.

            Given the table:

            >>> t = B(b'ABC').pad(256, 'zeros')

            The bytes 0, 1 and 2 of the following byte string
            are translated to A, B and C respectively

            >>> s = B([0, 1, 2])
            >>> s.map(t)
            b'ABC'

            But other mapping are possible.

            If <table> is a dictionary, the mapping is by value:
            each byte is looked up in the dictionary and the value
            returned is its replacement.

            >>> s.map({0: b'A', 1: b'B', 2: b'C'})
            b'ABC'

            If two tables are given, they must have the same length
            and the mapping is by value: the ith value in the table
            of the left is mapped to the ith value of the right.

            >>> s.map([0, 1, 2], [b'A', b'B', b'C'])
            b'ABC'

            An iterator and a callable are supported too. The iterator
            must return tuples to map one item to another and the
            callable must accept one item and return its replacement

            >>> s.map(zip([0, 1, 2], [b'A', b'B', b'C']))
            b'ABC'

            >>> s.map(lambda n: [b'A', b'B', b'C'][n])
            b'ABC'

            The callables can raise LookupError or IndexError to signal
            that there is no a valid mapping for the given byte (see
            "default mapping" below). Returning None will mark the bytes
            for deletion (see "delete bytes" below).

            Note: the callable will be called 256 times to generate the
            mapping for all the possible bytes. It will *not* be called
            per each byte of <self>. For that use the standar Python
            function <map> or a for-loop.

            For all the possible mappings, inputs and outputs can be
            integers (0 <= i < 256), bytes, bytearrays or
            immutable or mutable byte strings (of length 1).

            With the exception of a single byte string of 256 values
            as a table, all the mappings are "incomplete": they define
            how to map a subset of the possible values that a byte string
            could have (256 to be precise).

            We can define a default mapping for them:

             - we can replace them by a default (fill = <default>)
             - we can leave them as they are (fill = -1)
             - we can delete them (fill = None)

            >>> s.map([(1, b'B')], fill=0x40)
            b'@B@'

            >>> s.map([(1, b'B')], fill=-1)
            b'\x00B\x02'

            >>> s.map([(1, b'B')], fill=None)
            b'B'

            Deleting some bytes is possible not only with fill=None but
            returning None from a callable

            >>> s.map(lambda x: b'B' if x == 1 else None)
            b'B'

            Also, we can define the set of bytes to delete from the
            <delete> parameter:

            >>> s.map([], delete={0x0, 0x2})
            b'\x01'

        '''
        if isinstance(table, dict):
            table = table.items()

        if table2 is not None:
            table = zip(table, table2)

        if isinstance(table, Callable):
            func = table
            table = []
            for b in range(256):
                try:
                    v = func(b)
                except LookupError:
                    v = b
                except IndexError:
                    v = b

                table.append((b, v))

        def as_int(obj):
            if isinstance(obj, (bytes, bytearray)):
                return obj[0]
            return int(obj)

        # by default do not delete anything. this is compatible with the
        # default of bytes.translate.
        delete_set = set(delete)
        if isinstance(table, Iterable) and not isinstance(table, bytes):
            if fill is None:
                # delete all of them by default
                delete_set = set(range(256))

            if fill == -1 or fill is None:
                tmp = list(range(256))
            else:
                tmp = [as_int(fill)] * 256

            for ix, v in table:
                # normalize the items as (int, int) values
                ix = as_int(ix)

                if v is None:
                    # None means delete it
                    delete_set.add(ix)
                    v = 0
                else:
                    # if it is not None means that we don't want to
                    # delete it. If the default is delete (fill is None),
                    # removing the item from the set makes sense
                    delete_set.discard(ix)
                    v = as_int(v)

                tmp[ix] = v

            table = bytes(tmp)

        deletechars = bytes(delete_set)
        return super().translate(table, deletechars)

    def tomutable(self):
        return MutableByteString(self)


class MutableByteString(MutableSequenceMixin, bytearray):
    ''' Enhanced version of a mutable byte string.

            >>> s = B(b'ABA', mutable=True)
            >>> isinstance(s, bytearray) and type(s) != bytearray
            True
    '''
    __slots__ = ()

    def __repr__(self):
        return repr(self.toimmutable())

    def toimmutable(self):
        return ImmutableByteString(self)

    def tobytes(self):
        return bytes(self)

    def toarray(self):
        return np.array(tuple(self))
