import base64, bisect
from cryptonita.bytestrings import MutableByteString, ImmutableByteString

'''
>>> from cryptonita.conv import as_bytes, transpose, B, uniform_length
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

         - from an iterable inclusing another string of bytes

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

        By default the result returned will be a immutable ByteString
        but you can get a mutable one as well:

            >>> b = as_bytes(b'AB')
            >>> isinstance(b, ImmutableByteString) and isinstance(b, bytes)
            True

            >>> b = as_bytes(b'AB', mutable=True)
            >>> isinstance(b, MutableByteString) and isinstance(b, bytearray)
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

    return MutableByteString(raw) if mutable else ImmutableByteString(raw)

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

def transpose(sequences):
    ''' Given a list of sequences, stack them, see them as a matrix,
        transpose it and return it as another list of sequences.

            >>> s1 = B('ABCD')
            >>> s2 = B('1234')
            >>> s3 = B('9876')

            >>> transpose([s1, s2, s3])
            ['A19', 'B28', 'C37', 'D46']

        If the lengths are different, it is not possible to transpose
        them because some of the output sequences will have missing bytes:

            >>> s2 = s2[:2] # two bytes less
            >>> s3 = s3[:3] # one byte less

            >>> transpose([s1, s2, s3])
            Traceback <...>
            ValueError: Sequences have different length: first sequence has 4 bytes but the 2th has 2.
        '''

    l = len(sequences[0])
    for i, seq in enumerate(sequences, 1):
        if len(seq) != l:
            raise ValueError("Sequences have different length: first sequence has %i bytes but the %ith has %i." % (
                l, i, len(seq)))

    output = []
    for i in range(l):
        output.append(B(seq[i] for seq in sequences))

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

            >>> l = uniform_length(list(seqs), drop=0.5)
            >>> l.sort()
            >>> l                   # byexample: +norm-ws
            ['987',
             'ABC',
             'ABC',
             'ABC']

            >>> l = uniform_length(list(seqs), drop=0)
            >>> l.sort()
            >>> l                   # byexample: +norm-ws
            ['12',
             '98',
             'AB',
             'AB',
             'AB']

            >>> l = uniform_length(list(seqs), drop=1)
            >>> l.sort()
            >>> l                   # byexample: +norm-ws
            ['ABCD',
             'ABCD']

        Alternatively, you can set the wanted length:

            >>> l = uniform_length(list(seqs), length=3)
            >>> l.sort()
            >>> l                   # byexample: +norm-ws
            ['987',
             'ABC',
             'ABC',
             'ABC']

        Note that the modifications are done *in place* and that the
        original sequences are *reordered* in an unspecified order.
    '''

    if length is not None:
        sequences[:] = [seq[:length] if len(seq) != length else seq
                        for seq in sequences if len(seq) >= length]
        return sequences

    sequences.sort(key=lambda seq: len(seq))
    slens = [len(seq) for seq in sequences]

    idx = min(int(drop * len(sequences)), len(sequences)-1)
    min_len = slens[idx]

    ilow = bisect.bisect_left(slens, min_len, 0, idx)
    ihi = bisect.bisect_right(slens, min_len, idx)

    # cut the too large
    sequences[ihi:] = [seq[:min_len] for seq in sequences[ihi:]]

    # drop all the sequences too short
    sequences = sequences[ilow:]

    return sequences
