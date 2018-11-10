import base64
import collections
import itertools
import math
import numbers

from cryptonita.stats import SequenceStatsMixin

'''
>>> # Convenient definitions
>>> from cryptonita.bytestring import as_bytes, B, ByteString, InfiniteStream

'''

def are_same_length_or_fail(a, b):
    if len(a) != len(b):
        raise ValueError("Mismatch lengths. Left string has %i bytes but right string has %i." % \
                            (len(a), len(b)))

def are_bytes_or_fail(val, name):
    if not isinstance(val, collections.ByteString):
        raise TypeError("The parameter '%s' should be an instance of %s but it is %s." % \
                            (name, bytes, type(val)))

def as_bytes(raw, encoding='ascii', return_bytestring=True):
    r'''
        Create a stream of bytes from a sequence from bytes or text (str).

         - from a <raw> sequence of bytes:

            >>> as_bytes(b'\x00\x01')
            '\x00\x01'

         - from an iterable of integers

            >>> as_bytes([0, 1])
            '\x00\x01'

         - from a ByteString

            >>> as_bytes(as_bytes(b'\x00\x01'))
            '\x00\x01'

         - from a text (str) we need to pass which encoding to use to decode
         the string to bytes:

            >>> as_bytes(u'AB', encoding='utf-8')
            'AB'

         - it is also supported an overloaded version of <encoding> to map
         a base 16, 64, ... string or bytes into a stream.

            >>> as_bytes(b'020b', encoding=16)
            '\x02\x0b'

         - we can do the same with a text (str). In this case we assume that
         the encoding to map the unicode to the raw bytes is 'ascii',
         then we use <encoding> to map it to its final state

            >>> as_bytes(u'020b', encoding=16)
            '\x02\x0b'

         - from an integer. We assume that the integer is a byte sequence of
         just one byte.

            >>> as_bytes(12)
            '\x0c'

        By default, the object returned is an enhanced version of a sequence
        of bytes. If you want the raw bytes set <return_bytestring> to False:

            >>> s = as_bytes(12)
            >>> isinstance(s, bytearray) and isinstance(s, ByteString)
            True

        '''
    # see a single byte as a byte string
    #   as_bytes(7) -> b'\x07'
    if isinstance(raw, int):
        raw = [raw]

    # for a unicode, encode it to bytes
    #   as_bytes(u'text', encoding='utf8') -> b'text' (encode: utf8)
    elif isinstance(raw, str):
        if isinstance(encoding, int):
            # if the encoding is an integer means that it is
            # for decoding the string later.
            # Assume that encoding is then 'ascii'
            enc = 'ascii'
        else:
            enc = encoding

        raw = raw.encode(enc, errors='strict')

    #   as_bytes([b'\x0A', b'\x0B']) -> b'\x0a\x0b'
    #   as_bytes(b'\x00') -> b'\x00'
    else:
        raw = raw

    # overloaded meaning of encoding, the new raw bytes are encoded
    # using base 16 (64, other) and we want to decode them.
    if isinstance(encoding, int):
        if encoding == 16:
            raw = raw.upper()
        raw = getattr(base64, 'b%idecode' % encoding)(raw)

    return ByteString(raw)

def load_bytes(fp, mode='rb', **k):
    ''' Open a file <fp> with mode <mode> (read - binary by default)
        and read and load each line as a ByteString.

        How each line should be processed can be controlled by the
        same parameters that can be used with as_bytes.
        The keyword parameters of load_bytes are passed to
        as_bytes directly.

        If <fp> is not a string, it is assumed that it is a file
        already open (and <mode> is ignored).
        '''
    if isinstance(fp, str):
        fp = open(fp, mode)

    return (as_bytes(line.strip(), **k) for line in fp)

# alias
B = as_bytes


class ByteString(bytearray, SequenceStatsMixin):
    r'''
        Enhance a string of bytes extending it with some convenient
        methods.

        First, it is a sequence of bytes:

            >>> s = ByteString(b'\x01\x02')

            >>> isinstance(s, bytearray)
            True

        It supports the same set of methods than any other bytes sequence
        does.

            >>> len(s)
            2

        Decoding (to decode the sequence of bytes into a unicode text):

            >>> t = s.decode(encoding='ascii')
            >>> isinstance(t, str)
            True

        But it also supports encoding (to encode the sequence using a
        base 16, 64, ... encoding schema):

            >>> s.encode(base=16)
            '0102'

        This also support some basic statistics:

            >>> s = B('ABA')
            >>> s.freq()
            Counter({65: 2, 66: 1})

            >>> s.most_common(n=1)
            (65,)

            >>> s.entropy()
            0.6365141682948<...>

            >>> list(s.iduplicates(distance=1, idx_of='first'))
            [0]

        See more information in the documentation of each method.

        '''

    def __repr__(self):
        return super().__repr__()[11:-1]

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
            are instances of ByteString:

                >>> isinstance(a[:2], ByteString)
                True

            '''
        v = super().__getitem__(idx)
        if isinstance(idx, slice):
            return ByteString(v)    # TODO, double copy?

        return v

    def ngrams(self, n):
        return Ngrams(self, n)

    def nblocks(self, n):
        return Nblocks(self, n)

    # TODO cache me
    def count_1s(self):
        return sum(_number_of_1s_in_byte[b] for b in self)

    def join(self, *others):
        raise NotImplementedError("Not yet")
        return B(bytes.join(self, *others))

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

        '''
        if not isinstance(other, InfiniteStream):
            are_same_length_or_fail(self, other)

        return ByteString((a ^ b for a, b in zip(self, other)))

    def __rxor__(self, other):
        return self ^ other

    def __add__(self, other):
        ''' Concatenate two byte strings.

                >>> a = B(b'ABC')
                >>> b = B(b'DE')

                >>> a + b
                'ABCDE'

                >>> isinstance(a+b, ByteString)
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

        return ByteString(super().__add__(other))   # TODO double copy?

    def __radd__(self, other):
        return ByteString(other) + self   # TODO double copy?

    def __iadd__(self, other):
        raise NotImplementedError("You cannot expand an byte string.")

    def __lshift__(self, other):
        r'''
                >>> s = B("ABCD")

                >>> s << B('E')
                'BCDE'

                >>> s << B('EFG')
                'DEFG'

                >>> s << B('EFGHIJK')
                'HIJK'

        '''
        n = len(other)

        if n == 0:
            return B(self)

        if n > len(self):
            return B(other[-len(self):])

        return self[n:] + other

    def inf(self):
        return InfiniteStream(self)

    def encode(self, base):
        r'''
            Encode the byte string using a x base (base 16, base 64, ...)

                >>> B('\x01\x02').encode(16)
                '0102'

            Combine this with the decoding capabilities of B (as_bytes) to create
            a (little inefficient) conversor between bases:

                >>> b16 = b"49276d206b696c6c696e6720796f757220627" + \
                ...       b"261696e206c696b65206120706f69736f6e6f" + \
                ...       b"7573206d757368726f6f6d"
                >>> B(b16, encoding=16).encode(64)
                'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

            '''

        return getattr(base64, 'b%iencode' % base)(self)

    def pad(self, n, scheme):
        r'''Pad the byte string and return a new byte string object.

            How many bytes to pad is controlled by <n>, how we should
            do it is controlled by <scheme>

            For example:

                >>> B('AAAAAAAAAAAA').pad(16, 'pkcs#7')
                'AAAAAAAAAAAA\x04\x04\x04\x04'

        '''
        if scheme == 'pkcs#7':
            npad = n - (len(self) % n)
            if npad == 0:
                npad = n

            padding = bytes([npad]) * npad
        else:
            raise ValueError("Unknow padding scheme '%s'" % scheme)

        return as_bytes(self + padding)

    def unpad(self, scheme):
        r'''
                >>> padded = B('AAAAAAAAAAAA').pad(16, 'pkcs#7')
                >>> padded.unpad('pkcs#7')
                'AAAAAAAAAAAA'

        '''
        if scheme == 'pkcs#7':
            n = self[-1]

            if n > 64 or self[-n:] != B(n) * n:
                raise ValueError("Bad padding '%s' with last byte %#x" %
                                        (scheme, n))

            return self[:-n]
        else:
            raise ValueError("Unknow padding scheme '%s'" % scheme)

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


class Ngrams(SequenceStatsMixin):
    ''' N-grams view of a byte string.

        A n-gram is a sequence of n bytes that overlaps
        each other.

            >>> s = B('ABCDE')
            >>> ngrams = s.ngrams(3)

            >>> list(ngrams)
            ['ABC', 'BCD', 'CDE']

        Shorter and larger sequences are ok

            >>> list(B('ABC').ngrams(3))
            ['ABC']

            >>> list(B('ABCDEFGHI').ngrams(3))
            ['ABC', 'BCD', 'CDE', 'DEF', 'EFG', 'FGH', 'GHI']

        But too short aren't

            >>> list(B('AB').ngrams(3))
            Traceback <...>
            <...>
            ValueError: The byte string has only 2 bytes. It is not possible to create even a single ngram of length 3.

        A n-gram sequence supports:

            >>> len(ngrams)
            3

            >>> ngrams[1]
            'BCD'

        But slicing is not supported (yet)

            >>> ngrams[1:2]
            Traceback <...>
            <...>
            TypeError: We don't support slicing (yet).

        This also support some basic statistics:

            >>> ngrams = B('ABABABC').ngrams(2)
            >>> ngrams.freq()           # TODO not yet!! # byexample: +skip
            Counter({b'AB': 3, b'BA': 2, b'BC': 1})

            >>> ngrams.most_common(n=2)        # TODO not yet!! # byexample: +skip
            ('AB', 'BA')

            >>> ngrams.entropy()        # TODO not yet!! # byexample: +skip
            1.0114042647073<...>

    '''
    __slots__ = ('_raw', '_n')

    def __init__(self, raw, n):
        if len(raw) < n:
            raise ValueError("The byte string has only %i bytes. It is not possible to create even a single ngram of length %i." % (len(raw), n))

        self._raw = raw
        self._n = n

    def __iter__(self):
        s = self._raw
        n = self._n
        return (s[i:i+n] for i in range(len(self)))

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            raise TypeError("We don't support slicing (yet).")

        return self._raw[idx:idx+self._n]

    def __len__(self):
        return len(self._raw) - self._n + 1

class Nblocks(SequenceStatsMixin):
    ''' N-blocks view of a byte string.

        A n-block is a sequence of n bytes that do not overlap
        each other.

            >>> s = B('ABCDEF')
            >>> nblocks = s.nblocks(3)

            >>> list(nblocks)
            ['ABC', 'DEF']

        When the length of a sequence is not a multiple of n, the last
        block will have less than n bytes

            >>> list(B('ABC').nblocks(3))
            ['ABC']

            >>> list(B('ABCDEFGHIJK').nblocks(3))
            ['ABC', 'DEF', 'GHI', 'JK']

            >>> len(B('ABCDEFGHIJK').nblocks(3))
            4


        A n-blok sequence supports:

            >>> len(nblocks)
            2

            >>> nblocks[1]
            'DEF'

        But slicing is not supported (yet)

            >>> nblocks[1:2]
            Traceback <...>
            <...>
            TypeError: We don't support slicing (yet).


        This also support some basic statistics:

            >>> nblocks = B('ABABCABAABBA').nblocks(2)
            >>> nblocks.freq()        # TODO not yet!! # byexample: +skip
            Counter({b'AB': 3, b'BA': 2, b'CA': 1})

            >>> nblocks.most_common(n=2)        # TODO not yet!! # byexample: +skip
            ('AB', 'BA')

            >>> nblocks.entropy()        # TODO not yet!! # byexample: +skip
            1.0114042647073<...>

    '''
    def __init__(self, raw, n):
        self._raw = raw
        self._n = n

    def __iter__(self):
        s = self._raw
        n = self._n
        return (s[i*n:(i+1)*n] for i in range(len(self)))

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            raise TypeError("We don't support slicing (yet).")

        n = self._n
        return self._raw[idx*n:(idx+1)*n]

    def __len__(self):
        return math.ceil(len(self._raw) / self._n)

class InfiniteStream(bytes):
    def __getitem__(self, idx):
        if isinstance(idx, slice):
            raise TypeError("We don't support slicing (yet).")

        return bytes.__getitem__(self, idx % bytes.__len__(self))

    def __iter__(self):
        r'''
            Return an iterator of this infinite stream of bytes.
            Basically we take a finite sequence and we repeat it
            infinite times:

                >>> s = InfiniteStream(b'\x01\x02')

                >>> i = iter(s)
                >>> next(i), next(i), next(i), next(i)
                (1, 2, 1, 2)

            '''
        return itertools.cycle(bytes.__iter__(self))

    def __repr__(self):
        return '.. ' + bytes.__repr__(self) + ' ..'

    def __len__(self):
        return math.inf

_number_of_1s_in_byte = [0] * 256
for i in range(len(_number_of_1s_in_byte)):
    _number_of_1s_in_byte[i] = (i & 1) + _number_of_1s_in_byte[i >> 1]

_number_of_1s_in_byte = tuple(_number_of_1s_in_byte)

