'''
>>> from cryptonita.toys.hashes.md4 import md4
'''

# Pure python implementation of MD4, modified to be useful
# for cryptonita
#
# Src: https://gist.githubusercontent.com/kangtastic/c3349fc4f9d659ee362b12d7d8c639b6/raw/3b3317e2987c68f21fb2393547b2b0593a265f14/md4.py
# License: WTFPL, version 2 (wtfpl.net).
# Copyright © 2019 James Seo <james@equiv.tech> (github.com/kangtastic).
import struct


def md4(
    msg,
    h0=0x67452301,
    h1=0xEFCDAB89,
    h2=0x98BADCFE,
    h3=0x10325476,
    forged_message_len=None,
):
    '''
    >>> md4(b'')
    '31d6cfe0d16ae931b73c59d7e0c089c0'

    >>> md4(b'The quick brown fox jumps over the lazy dog')
    '1bee69a46ba811185c194762abaeae90'

    >>> md4(b'BEES')
    '501af1ef4b68495b5b7e37b15b4cda68'
    '''

    msg = bytes(msg)

    mask = 0xFFFFFFFF

    # Pre-processing: Total length is a multiple of 512 bits.
    ml = len(msg) * 8
    msg += b"\x80"
    msg += b"\x00" * (-(len(msg) + 8) % 64)
    if forged_message_len is None:
        msg += struct.pack("<Q", ml)
    else:
        msg += struct.pack("<Q", forged_message_len * 8)

    # Process the message in successive 512-bit chunks.
    chunks = [msg[i:i + 64] for i in range(0, len(msg), 64)]

    for chunk in chunks:
        X, h = list(struct.unpack("<16I", chunk)), [h0, h1, h2, h3]

        # Round 1.
        Xi = [3, 7, 11, 19]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = n, Xi[n % 4]
            hn = h[i] + F(h[j], h[k], h[l]) + X[K]
            h[i] = lrot32(hn & mask, S)

        # Round 2.
        Xi = [3, 5, 9, 13]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = n % 4 * 4 + n // 4, Xi[n % 4]
            hn = h[i] + G(h[j], h[k], h[l]) + X[K] + 0x5A827999
            h[i] = lrot32(hn & mask, S)

        # Round 3.
        Xi = [3, 9, 11, 15]
        Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = Ki[n], Xi[n % 4]
            hn = h[i] + H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
            h[i] = lrot32(hn & mask, S)

        h0, h1, h2, h3 = [
            ((v + n) & mask) for v, n in zip([h0, h1, h2, h3], h)
        ]

    return "".join(
        f"{value:02x}" for value in struct.pack("<4L", *[h0, h1, h2, h3])
    )


def F(x, y, z):
    return (x & y) | (~x & z)


def G(x, y, z):
    return (x & y) | (x & z) | (y & z)


def H(x, y, z):
    return x ^ y ^ z


def lrot32(value, n):
    lbits, rbits = (value << n) & 0xFFFFFFFF, value >> (32 - n)
    return lbits | rbits


def main():
    # Import is intentionally delayed.
    import sys

    if len(sys.argv) > 1:
        messages = [msg.encode() for msg in sys.argv[1:]]
        for message in messages:
            print(MD4(message).hexdigest())
    else:
        messages = [
            b"", b"The quick brown fox jumps over the lazy dog", b"BEES"
        ]
        known_hashes = [
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "1bee69a46ba811185c194762abaeae90",
            "501af1ef4b68495b5b7e37b15b4cda68",
        ]

        print("Testing the MD4 class.")
        print()

        for message, expected in zip(messages, known_hashes):
            print("Message: ", message)
            print("Expected:", expected)
            print("Actual:  ", MD4(message).hexdigest())
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
