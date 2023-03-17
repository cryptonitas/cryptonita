import struct
from cython import uint, cfunc, p_char
import cython


# Adapted from https://github.com/ajalt/python-sha1
# Licensed as MIT
# Cythonized for Cryptonita
@cfunc
def lrotate_32(n: uint, r: uint) -> uint:
    mask: uint = 0xffffffff
    return ((n << r) | (n >> (32 - r))) & mask


def sha1(msg: p_char):
    h = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    ix = 0
    chunk = msg[ix:ix + 64]
    while len(chunk) == 64:
        h = _process_chunk(chunk, *h)
        ix += 64
        chunk = msg[ix:ix + 64]

    message = bytes(chunk)
    message_byte_length = len(msg)

    # append the bit '1' to the message
    message += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message_bit_length = message_byte_length * 8
    message += struct.pack(b'>Q', message_bit_length)

    # At this point, the length of the message is either 64 or 128 bytes.
    assert len(message) in (64, 128)
    h = _process_chunk(message[:64], *h)
    if len(message) == 128:
        h = _process_chunk(message[64:], *h)

    # return the digest (bytes)
    return b''.join(struct.pack('>I', x) for x in h)


def _process_chunk(chunk, h0, h1, h2, h3, h4):
    assert len(chunk) == 64

    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = lrotate_32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    # Initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = (
            (lrotate_32(a, 5) + f + e + k + w[i]) & 0xffffffff, a,
            lrotate_32(b, 30), c, d
        )

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4
