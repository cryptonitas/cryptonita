'''
>>> from cryptonita.conv import B           # byexample: +timeout=10
>>> from cryptonita.conv import as_bytes, transpose, uniform_length, repack, join_bytestrings
>>> from cryptonita.bytestrings import MutableByteString, ImmutableByteString
'''


def as_bytes(raw, encoding='ascii', mutable=False):
    r'''
        Create a string of bytes from a sequence from bytes or text (str).

         - from a <raw> sequence of bytes:

            >>> as_bytes(b'\x00\x01')
            '\x00\x01'

         - from an iterable of integers

            >>> as_bytes([0, 1])
            '\x00\x01'

         - from flatten 1-dimentional arrays (numpy)

            >>> import numpy as np
            >>> as_bytes(np.array([0, 1]))
            '\x00\x01'

            >>> as_bytes(np.array([[0], [1]]))
            Traceback<...>
            ValueError: only 1-dimentional arrays are supported but array of shape (2, 1) was given

         - from an iterable including another string of bytes

            >>> as_bytes(as_bytes(b'\x00\x01'))
            '\x00\x01'

         - from a text (str) we need to pass which encoding to use to decode
         the string to bytes:

            >>> as_bytes(u'AB', encoding='utf-8')
            'AB'

         - from a text (str) we support special encodings 'upper' and 'lower'.
         This is used for academic cryptographers to represent text using ASCII
         letters only (all uppercase or all lowercase) with spaces
         each N letters (typically 5).

            >>> as_bytes(u'abcd', encoding='lower')
            '\x00\x01\x02\x03'

            >>> as_bytes(u'AAABB CCCDD EEE', encoding='upper')
            '\x00\x00\x00\x01\x01\x02\x02\x02\x03\x03\x04\x04\x04'

            >>> as_bytes(u'abcde ABCDE', encoding='upper')
            Traceback<...>
            ValueError: text must contain uppercase plus spaces only.

         - it is also supported an overloaded version of <encoding> to map
         a base 16, 64, ... string or bytes into a stream.

            >>> as_bytes(b'020b', encoding=16)
            '\x02\x0b'

         - for convenience, spaces and newlines are ignored when <encoding>
         is 16, 64, ...

            >>> as_bytes(b'02 0b\n03', encoding=16)
            '\x02\x0b\x03'

         - we can do the same with a text (str). In this case we assume that
         the encoding to map the unicode to the raw bytes is 'ascii',
         then we use <encoding> to map it to its final state

            >>> as_bytes(u'020b', encoding=16)
            '\x02\x0b'

         - from an integer. We assume that the integer is a byte sequence of
         just one byte.

            >>> as_bytes(12)
            '\x0c'

        By default the result returned will be a immutable ByteString
        but you can get a mutable one as well:

            >>> b = as_bytes(b'AB')
            >>> isinstance(b, ImmutableByteString) and isinstance(b, bytes)
            True

            >>> b = as_bytes(b'AB', mutable=True)
            >>> isinstance(b, MutableByteString) and isinstance(b, bytearray)
            True

        '''
    if hasattr(raw, 'read'):
        raw = raw.read()

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
        elif encoding in ('upper', 'lower'):
            enc = 'ascii'
        else:
            enc = encoding

        raw = raw.encode(enc, errors='strict')

    elif getattr(np, 'ndarray',
                 None) is not None and isinstance(raw, np.ndarray):
        if len(raw.shape) != 1:
            raise ValueError(
                "only 1-dimentional arrays are supported but array of shape %s was given"
                % str(raw.shape)
            )
        raw = list(raw)

    #   as_bytes([b'\x0A', b'\x0B']) -> b'\x0a\x0b'
    #   as_bytes(b'\x00') -> b'\x00'
    else:
        raw = raw

    # support for 'academic' encoded strings
    if encoding in ('upper', 'lower'):
        raw = raw.replace(b' ', b'')
        if (encoding == 'upper' and not raw.isupper()) or \
                (encoding == 'lower' and not raw.islower()):
            raise ValueError(
                "text must contain %scase plus spaces only." % encoding
            )

        offset = ord('A') if encoding == 'upper' else ord('a')
        raw = bytes(r - offset for r in raw)

    # overloaded meaning of encoding, the new raw bytes are encoded
    # using base 16 (64, other) and we want to decode them.
    if isinstance(encoding, int):
        raw = raw.replace(b' ', b'').replace(b'\n', b'')
        if encoding == 16:
            raw = raw.upper()

        if encoding == 58:
            raw = base58.b58decode(raw)
        else:
            raw = getattr(base64, 'b%idecode' % encoding)(raw)

    return MutableByteString(raw) if mutable else ImmutableByteString(raw)


def load_bytes(fp, mode='rt', **k):
    r'''Open a file <fp> with mode <mode> (read - text by default)
        and load a sequence of ByteStrings, one per line.

        During the reading, each line is stripped and how each ByteStrings
        is built from each line is controlled by the
        same parameters that can be used with as_bytes.

        If <fp> is not a string, it is assumed that it is a file
        already open (and <mode> is ignored).

        Return an iterator of ByteStrings.

        '''
    if isinstance(fp, str):
        fp = open(fp, mode)

    return (as_bytes(line.strip(), **k) for line in fp)


# alias
B = as_bytes


def transpose(sequences, allow_holes=False, fill_value=None):
    ''' Given a list of sequences, stack them, see them as a matrix,
        transpose it and return it as another list of sequences.

            >>> s1 = B('ABCD')
            >>> s2 = B('1234')
            >>> s3 = B('9876')

            >>> print(s1, s2, s3, sep='\n')
            b'ABCD'
            b'1234'
            b'9876'

            >>> transpose([s1, s2, s3])
            ['A19', 'B28', 'C37', 'D46']

            >>> print(*transpose([s1, s2, s3]), sep='\n')
            b'A19'
            b'B28'
            b'C37'
            b'D46'

        If the lengths are different, it is not possible to transpose
        them because some of the output sequences will have missing bytes:

            >>> s2 = s2[:2] # two bytes less
            >>> s3 = s3[:3] # one byte less

            >>> print(s1, s2, s3, sep='\n')
            b'ABCD'
            b'12'
            b'987'

            >>> transpose([s1, s2, s3])
            Traceback <...>
            ValueError: Sequences have different length: first sequence has 4 bytes but the 2th has 2.

        Holes are allowed if explicitly said so:

            >>> transpose([s1, s2, s3], allow_holes=True)
            ['A19', 'B28', 'C7', 'D']

            >>> print(*transpose([s1, s2, s3], allow_holes=True), sep='\n')
            b'A19'
            b'B28'
            b'C7'
            b'D'

        Fill values are possible too:

            >>> transpose([s1, s2, s3], allow_holes=True, fill_value=b'.'[0])
            ['A19', 'B28', 'C.7', 'D..']

            >>> print(*transpose([s1, s2, s3], allow_holes=True, fill_value=b'.'[0]), sep='\n')
            b'A19'
            b'B28'
            b'C.7'
            b'D..'
        '''

    l = len(sequences[0])
    if not allow_holes:
        for i, seq in enumerate(sequences, 1):
            if len(seq) != l:
                raise ValueError(
                    "Sequences have different length: first sequence has %i bytes but the %ith has %i."
                    % (l, i, len(seq))
                )

    output = []
    for column in itertools.zip_longest(*sequences, fillvalue=fill_value):
        output.append(B(b for b in column if b is not None))

    return output


def uniform_length(sequences, *, drop=0, length=None):
    ''' Given a list of sequences, stack them and see them as a matrix:
            >>> seqs = [B('ABCD'), B('12'), B('987'), B('ABC'), B('ABCD')]
            >>> seqs                    # byexample: +norm-ws
            ['ABCD',
             '12',
             '987',
             'ABC',
             'ABCD']

        Then, drop the sequences that are too short and cut the larger ones
        until get all the sequences of the same length.

        How many sequences are we willing to drop can be controlled by the
        <drop> parameter (a percentage).

            >>> uniform_length(seqs, drop=0.5)     # byexample: +norm-ws
            ['ABC',
             '987',
             'ABC',
             'ABC']

            >>> uniform_length(seqs, drop=0)     # byexample: +norm-ws
            ['AB',
             '12',
             '98',
             'AB',
             'AB']

            >>> uniform_length(seqs, drop=1)     # byexample: +norm-ws
            ['ABCD',
             'ABCD']

        Alternatively, you can set the wanted length:

            >>> uniform_length(seqs, length=3)     # byexample: +norm-ws
            ['ABC',
             '987',
             'ABC',
             'ABC']
    '''

    if length is not None:
        return [
            seq[:length] if len(seq) != length else seq for seq in sequences
            if len(seq) >= length
        ]

    sequences, original_idxs = zip(
        *sorted(
            ((s, idx) for idx, s in enumerate(sequences)),
            key=lambda seq_idx: (len(seq_idx[0]), seq_idx[1])
        )
    )

    sequences = list(sequences)

    slens = [len(seq) for seq in sequences]

    idx = min(int(drop * len(sequences)), len(sequences) - 1)
    min_len = slens[idx]

    ilow = bisect.bisect_left(slens, min_len, 0, idx)
    ihi = bisect.bisect_right(slens, min_len, idx)

    # cut the too large
    sequences[ihi:] = [seq[:min_len] for seq in sequences[ihi:]]

    # drop all the sequences too short
    sequences = sequences[ilow:]

    # restore the original order
    sequences, _ = zip(
        *sorted(zip(sequences, original_idxs), key=lambda seq_idx: seq_idx[1])
    )

    return list(sequences)


def repack(iterable, ifmt, ofmt):
    ''' Repack each element in <iterable> packing them with <ifmt>
        first and then unpacking them with <ofmt>.

        See the documentation of the Python standard module struct.

        To repack a list of numbers of 4 bytes into a sequence
        of bytes in big endian we do:

        >>> list(repack([0xAABBCCDD, 0xA1B2C3D4], ifmt='>I', ofmt='>1s1s1s1s'))
        [b'\xaa', b'\xbb', b'\xcc', b'\xdd', b'\xa1', b'\xb2', b'\xc3', b'\xd4']

        To get a single Bytes object you could do:

        >>> B.join(repack([0xAABBCCDD, 0xA1B2C3D4], ifmt='>I', ofmt='>1s1s1s1s'))
        '\xaa\xbb\xcc\xdd\xa1\xb2\xc3\xd4'

        And from bytes to integers:

        >>> a, b = list(repack(B('ABCDAABB').nblocks(4), ifmt='>4s', ofmt='>I'))
        >>> hex(a), hex(b)
        ('0x41424344', '0x41414242')

        Any input/output formats are valid as long as they have the same
        'size':

        >>> list(repack([1], ifmt='>I', ofmt='>H'))
        Traceback <...>
        ValueError: Format sizes mismatch: input >I (4 bytes), output >H (2 bytes)


        '''
    isize = struct.calcsize(ifmt)
    osize = struct.calcsize(ofmt)
    if isize != osize:
        raise ValueError("Format sizes mismatch: input " +\
                         "%s (%i bytes), output %s (%i bytes)" % (
                             ifmt, isize,
                             ofmt, osize))

    for i in iterable:
        for o in struct.unpack(ofmt, struct.pack(ifmt, i)):
            yield o


def join_bytestrings(*seqs):
    ''' Join the sequences of byte strings.

        >>> seqs = [B('ABC'), B('DE')]
        >>> join_bytestrings(seqs)
        'ABCDE'
        '''
    return B('').join(*seqs)


B.join = join_bytestrings

# Push all the imports to the bottom of the file so anyone wanting to import
# and use as_bytes and others can do it without cycling imports
# This is true for imports of as_bytes by *ByteString and their dependencies.
import base64, base58, bisect, struct, itertools
from cryptonita.bytestrings import MutableByteString, ImmutableByteString

from cryptonita.deps import importdep

np = importdep('numpy')
