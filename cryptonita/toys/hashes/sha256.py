# Pure python implementation of SHA256, modified to be useful
# for cryptonita
#
# From https://github.com/keanemind/Python-SHA-256
# License MIT
'''
>>> from cryptonita.toys.hashes.sha256 import sha256, sha224
'''

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def sha256(
    message,

    # Setting Initial Hash Value
    h0=0x6a09e667,
    h1=0xbb67ae85,
    h2=0x3c6ef372,
    h3=0xa54ff53a,
    h4=0x510e527f,
    h5=0x9b05688c,
    h6=0x1f83d9ab,
    h7=0x5be0cd19,
    forged_message_len=None
):
    """
    >>> sha256(b'')
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    >>> sha256(b'The quick brown fox jumps over the lazy dog')
    'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'

    >>> sha256(b'BEES')
    'd3c1c8a7366e3decde2ad0fe2d9a4fe7e0441f3d5653c0a717564ce9c3bb844c'
    """

    message = bytes(message)

    # Padding
    length = len(message) * 8  # len(message) is number of BYTES!!!
    message += b'\x80'
    while (len(message) * 8 + 64) % 512 != 0:
        message += b'\x00'

    if forged_message_len is None:
        message += length.to_bytes(8, 'big')  # pad to 8 bytes or 64 bits
    else:
        message += (forged_message_len *
                    8).to_bytes(8, 'big')  # pad to 8 bytes or 64 bits

    assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"

    # Parsing
    blocks = []  # contains 512-bit chunks of message
    for i in range(0, len(message), 64):  # 64 bytes is 512 bits
        blocks.append(message[i:i + 64])

    # SHA-256 Hash Computation
    for message_block in blocks:
        # Prepare message schedule
        message_schedule = []
        for t in range(0, 64):
            if t <= 15:
                # adds the t'th 32 bit word of the block,
                # starting from leftmost word
                # 4 bytes at a time
                message_schedule.append(
                    bytes(message_block[t * 4:(t * 4) + 4])
                )
            else:
                term1 = _sigma1(int.from_bytes(message_schedule[t - 2], 'big'))
                term2 = int.from_bytes(message_schedule[t - 7], 'big')
                term3 = _sigma0(
                    int.from_bytes(message_schedule[t - 15], 'big')
                )
                term4 = int.from_bytes(message_schedule[t - 16], 'big')

                # append a 4-byte byte object
                schedule = ((term1 + term2 + term3 + term4) %
                            2**32).to_bytes(4, 'big')
                message_schedule.append(schedule)

        assert len(message_schedule) == 64

        # Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Iterate for t=0 to 63
        for t in range(64):
            t1 = (
                (
                    h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                    int.from_bytes(message_schedule[t], 'big')
                ) % 2**32
            )

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        # Compute intermediate hash value
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32

    return '%08x%08x%08x%08x%08x%08x%08x%08x' % (
        h0, h1, h2, h3, h4, h5, h6, h7
    )


def sha224(
    message,

    # Setting Initial Hash Value (different than the used by SHA-256)
    h0=0xc1059ed8,
    h1=0x367cd507,
    h2=0x3070dd17,
    h3=0xf70e5939,
    h4=0x68581511,
    h5=0xffc00b31,
    h6=0x64f98fa7,
    h7=0xbefa4fa4,
    forged_message_len=None
):
    """
    >>> sha224(b'')
    'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'

    >>> sha224(b'The quick brown fox jumps over the lazy dog')
    '730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525'

    >>> sha224(b'BEES')
    '72d66b7a0ff879cc7f0f0e4c778cdd53e4a04d50466ef2650438fb6f'
    """

    h = sha256(message, h0, h1, h2, h3, h4, h5, h6, h7, forged_message_len)
    return h[:-8]


def _sigma0(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 7) ^ _rotate_right(num, 18) ^ (num >> 3))
    return num


def _sigma1(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 17) ^ _rotate_right(num, 19) ^ (num >> 10))
    return num


def _capsigma0(num: int):
    """As defined in the specification."""
    num = (
        _rotate_right(num, 2) ^ _rotate_right(num, 13)
        ^ _rotate_right(num, 22)
    )
    return num


def _capsigma1(num: int):
    """As defined in the specification."""
    num = (
        _rotate_right(num, 6) ^ _rotate_right(num, 11)
        ^ _rotate_right(num, 25)
    )
    return num


def _ch(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (x & z) ^ (y & z)


def _rotate_right(num: int, shift: int, size: int = 32):
    """Rotate an integer right."""
    return (num >> shift) | (num << size - shift)
