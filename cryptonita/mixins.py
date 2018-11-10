from cryptonita.helpers import are_same_length_or_fail, are_bytes_or_fail
import base64

'''
>>> # Convenient definitions
>>> from cryptonita import B
>>> from cryptonita.immutable_bytestring import ImmutableByteString
>>> from cryptonita.mutable_bytestring import MutableByteString

'''

class SequenceMixin:
    __slots__ = ()

    def __getitem__(self, idx):
        ''' Get a byte or a slice of bytes.

            Use an index (number) to get a single byte:

                >>> a = B(b'ABCD')
                >>> a[0], a[-1]
                (65, 68)

            Use a slice object to get a slice of bytes:

                >>> a[:], a[:2], a[1:3]
                ('ABCD', 'AB', 'BC')

            The returned slices are *copies* of the original and
            are instances of ImmutableByteString:

                >>> isinstance(a[:2], ImmutableByteString)
                True

            '''
        v = super().__getitem__(idx)
        if isinstance(idx, slice):
            return type(self)(v)    # TODO, double copy?

        return v

    def copy(self):
        return type(self)(super().copy())   # TODO, double copy?

    def __xor__(self, other):
        r'''
            Compute the xor between two strings of bytes with the same length.

                >>> a = B('1c0111001f010100061a024b53535009181c', encoding=16)
                >>> b = B('686974207468652062756c6c277320657965', encoding=16)

                >>> c = a ^ b
                >>> c.encode(16)
                '746865206B696420646F6E277420706C6179'

            If the two strings have different lengths, the operation is undefined.
            Should we repeat the shorter string to match the length of the other
            or should we truncate the longer instead to match the length of the
            shorter?

            Different lengths are not allowed

                >>> short = B('\x11\x10\x00\x00')
                >>> a ^ short
                Traceback (most recent call last):
                <...>
                ValueError: Mismatch lengths. Left string has 18 bytes but right string has 4.

            There is an exception to this rule: if one of the stream is an
            infinite sequence, then (obviously) the only logical action is to
            truncate it to match the length of the shorter sequence and compute
            the xor:

                >>> plaintext = B("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
                >>> key = B("ICE")

                >>> (plaintext ^ key.inf()).encode(16)
                ('0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272A'
                 '282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F')

            Inplace is allowed too:

                >>> a ^= b
                >>> a == c
                True

        '''
        if not isinstance(other, InfiniteStream):
            are_same_length_or_fail(self, other)

        return type(self)((a ^ b for a, b in zip(self, other)))

    def __rxor__(self, other):
        return self ^ other

    def __add__(self, other):
        ''' Concatenate two byte strings.

                >>> a = B(b'ABC')
                >>> b = B(b'DE')

                >>> a + b
                'ABCDE'

                >>> isinstance(a+b, ImmutableByteString)
                True

            Concatenate them even if they are plain bytearrays:

                >>> b'123' + a
                '123ABC'

                >>> a + b'123'
                'ABC123'

            The concatenation cannot be inplace (the string cannot be
            expended):

                >>> a += b
                Traceback <...>
                NotImplementedError: You cannot expand an byte string.
            '''

        return type(self)(super().__add__(other))   # TODO double copy?

    def __radd__(self, other):
        return type(self)(other) + self   # TODO double copy?

    def __iadd__(self, other):
        raise NotImplementedError("You cannot expand an byte string.")

    def __mul__(self, other):
        ''' Repeat a byte string <n> times.

                >>> a = B(b'ABC')

                >>> a * 3
                'ABCABCABC'

                >>> 2 * a
                'ABCABC'

                >>> isinstance(a*2, ImmutableByteString)
                True

            A non-positive number is allowed and returns an empty string

                >>> a * 0
                ''

                >>> a * -1
                ''

            The repeat cannot be inplace (the string cannot be
            expended):

                >>> a *= 2
                Traceback <...>
                NotImplementedError: You cannot expand an byte string.
            '''
        return type(self)(super().__mul__(other))   # TODO double copy?

    def __rmul__(self, other):
        return type(self)(super().__mul__(other))   # TODO double copy?

    def __imul__(self, other):
        raise NotImplementedError("You cannot expand an byte string.")

    def __lshift__(self, other):
        ''' Pushes the <other> string into self shifting all the
            bytes to the left.

            This does not increase or shrink the string length
            and returns a copy always.

                >>> s = B("ABCD")

                >>> s << B('E')
                'BCDE'

            Other than ByteString can be pushed too:

                >>> s << b'EFG'
                'DEFG'

            Pushing a much larger string will basically override
            the original content:

                >>> s << B('EFGHIJK')
                'HIJK'

            *Beware:* each push or shift involves copying all the byte
            string which can be really slow.

        '''
        n = len(other)

        if n == 0:
            return type(self)(self)

        if n > len(self):
            return type(self)(other[-len(self):])
        else:
            return self[n:] + other

    def encode(self, base):
        r'''
            Encode the byte string using base <x> (base 16, base 64, ...)

                >>> B('\x01\x02').encode(16)
                '0102'

            Combine this with the decoding capabilities of B (conv.as_bytes)
            to create a (little inefficient) conversor between bases:

                >>> b16 = b"49276d206b696c6c696e6720796f757220627" + \
                ...       b"261696e206c696b65206120706f69736f6e6f" + \
                ...       b"7573206d757368726f6f6d"
                >>> B(b16, encoding=16).encode(64)
                'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

            Use decode to build a str object from the bytes.

                >>> t = B(b'ABC').decode(encoding='ascii')
                >>> isinstance(t, str)
                True
            '''

        return getattr(base64, 'b%iencode' % base)(self)

    def pad(self, n, scheme):
        r'''Pad the byte string up to <n> bytes-boundaries using
            the padding <scheme> and return a new byte string object.

                >>> B('AAAAAAAAAAAA').pad(16, 'pkcs#7')
                'AAAAAAAAAAAA\x04\x04\x04\x04'

                >>> B('AAAAAAAAAAAABBBB').pad(16, 'pkcs#7')
                'AAAAAAAAAAAABBBB\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

                >>> isinstance(B('A').pad(16, 'pkcs#7'), ImmutableByteString)
                True

        '''
        if scheme == 'pkcs#7':
            assert n > 0
            npad = n - (len(self) % n)
            if npad == 0:
                npad = n

            padding = type(self)([npad]) * npad
        else:
            raise ValueError("Unknow padding scheme '%s'" % scheme)

        return self + padding

    def unpad(self, scheme):
        r'''
                >>> padded = B('AAAAAAAAAAAA').pad(16, 'pkcs#7')
                >>> padded.unpad('pkcs#7')
                'AAAAAAAAAAAA'

        '''
        if scheme == 'pkcs#7':
            n = self[-1]

            if n > 64 or self[-n:] != type(self)([n]) * n:
                raise ValueError("Bad padding '%s' with last byte %#x" %
                                        (scheme, n))

            return self[:-n]
        else:
            raise ValueError("Unknow padding scheme '%s'" % scheme)

    def inf(self):
        return InfiniteStream(self)

    def ngrams(self, n):
        return NgramsView(self, n)

    def nblocks(self, n):
        return NblocksView(self, n)


class MutableSequenceMixin(SequenceMixin):
    __slots__ = ()

    def __ixor__(self, other):
        ''' xor <other> with <self> in place.

                >>> s = B(b'\x01\x02', mutable=True)

                >>> s ^= b'\x01\x01'
                >>> s
                '\x00\x03'

                >>> s ^= B(b'A').inf()
                >>> s
                'AB'

            See SequenceMixin.__xor__ for more about this.
        '''
        if not isinstance(other, InfiniteStream):
            are_same_length_or_fail(self, other)

        for idx in range(len(self)):
            super().__setitem__(idx, super().__getitem__(idx) ^ other[idx])

        return self

    def __ilshift__(self, other):
        ''' Shift to the left <other> into <self> in place.

                >>> s = B(b'ABC', mutable=True)

                >>> s <<= b'DE'
                >>> s
                'CDE'

                >>> s <<= b'FGHI'
                >>> s
                'GHI'

            See SequenceMixin.__lshift__ for more about this.
        '''
        n = len(other)

        if n == 0:
            return self

        if n > len(self):
            self[:] = other[-len(self):]
        else:
            self[:-n] = self[n:]
            self[-n:] = other

        return self

class ByteStatsMixin:
    __slots__ = ()

    # TODO cache me
    def count_1s(self):
        return sum(_number_of_1s_in_byte[b] for b in self)

    def hamming_distance(self, m2):
        r'''
            Return the Hamming distance between self and <m2>.

            >>> m1 = B('this is a test')
            >>> m2 = B('wokka wokka!!!')

            >>> m1.hamming_distance(m2)
            37

            The Hamming (or edit) distance is the count of how many bits
            these two string differ. It is defined for strings of the same
            lengths, so the following will fail:

            >>> m1.hamming_distance(m1 + m1)
            Traceback (most recent call last):
            <...>
            ValueError: Mismatch lengths. Left string has 14 bytes but right string has 28.

        '''

        x = self ^ m2
        return x.count_1s()

_number_of_1s_in_byte = [0] * 256
for i in range(len(_number_of_1s_in_byte)):
    _number_of_1s_in_byte[i] = (i & 1) + _number_of_1s_in_byte[i >> 1]

_number_of_1s_in_byte = tuple(_number_of_1s_in_byte)

import collections
import itertools as itools
from cryptonita.stats import entropy

class SequenceStatsMixin:
    __slots__ = ()
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

from cryptonita.views import InfiniteStream, NgramsView, NblocksView