from cryptonita import B
import string
from cryptonita.deps import importdep

gp = importdep('gmpy2')
'''
>>> from cryptonita import B                    # byexample: +timeout=10
>>> from cryptonita.toys.substitution_ciphers import *
'''


def atbash(ptext, alphabet=B(string.ascii_lowercase), dec=False):
    ''' Atbash encrypts each letter of the alphabet by its
        mirror letter.

        Given the following alphabet

        >>> alphabet = B('abcde')

        The mirror would be

        >>> alphabet[::-1]
        'edcba'

        Then, the encryption follows replacing each letter of
        the plaintext by the mirrored alphabet

        >>> ctext = atbash(B('aabeec'), alphabet)
        >>> ctext
        'eedaac'

        Encrypting again yields the plaintext (it is a reciprocal cipher)

        >>> atbash(ctext, alphabet)
        'aabeec'

        References:
        https://es.wikipedia.org/wiki/Atbash
        '''

    tr = dict(zip(alphabet, alphabet[::-1]))
    return substitute(ptext, tr)


def rot13(ptext, alphabet=B(string.ascii_lowercase), dec=False):
    ''' Split the alphabet in halves and swap them, using this
        as the substitution table.

        This is the same than shifting the alphabet N positions
        where N is the half of the length of the alphabet.

        When the alphabet is the ascii english letters ignoring
        the case, N is 13: that's why it is called "rot 13"

        >>> rot13(B('cryptonita'))
        'pelcgbavgn'

        >>> rot13(B('aabeec'), alphabet=B('abcde'))
        'ccdbbe'

        When the alphabet is divisible by 2, encrypting again
        decryptes the ciphertext (it is a reciprocal cipher)

        >>> rot13(B('pelcgbavgn'))
        'cryptonita'

        However, if the alphabet is not divisible by 2, the second
        encryption is "shifted" by one. To decrypt a ciphertext
        in this case pass dec=True.

        >>> rot13(B('ccdbbe'), alphabet=B('abcde'), dec=True)
        'aabeec'

        References:
        https://en.wikipedia.org/wiki/ROT13
        '''

    shift = len(alphabet) // 2
    if len(alphabet) % 2 != 0 and dec:
        shift += 1

    return caesar(ptext, alphabet, key=shift)


def caesar(ptext, alphabet=B(string.ascii_lowercase), key=3, dec=False):
    ''' Shit by 3 the alphabet and use that as the substitution
        table.

        >>> caesar(B('ave caesar'))
        'dyh fdhvdu'

        The alphabet and the shitf key can be changed:

        >>> caesar(B('ave caesar'), B('avecsr'), key=5)
        'rav ervcrs'

        To decrypt a ciphertext, encrypt again with a
        key equal -k where k is the original key (3 by default)
        or just pass the 'dec' flag

        >>> caesar(B('dyh fdhvdu'), dec=True)
        'ave caesar'

        >>> caesar(B('rav ervcrs'), B('avecsr'), key=-5)
        'ave caesar'

        References:
        https://en.wikipedia.org/wiki/Caesar_cipher
        '''
    shift = key % len(alphabet)

    enc_alphabet = alphabet[shift:] + alphabet[:shift]
    tr = dict(
        zip(enc_alphabet, alphabet) if dec else zip(alphabet, enc_alphabet)
    )

    return substitute(ptext, tr)


def affine(ptext, key, alphabet=B(string.ascii_lowercase), dec=False):
    '''
        Perform an affine transformation of the plaintext to obtain
        a ciphertext given an alphabet.

        An affine transformation requires two secret values, 'a' and 'b'
        (the key) where 'a' must be coprime of the length of the
        alphabet 'm'. This means that the only common divisor between 'a'
        and 'm' is 1.

        With this, each symbol 'x' of the alphabet is transformed as:
            a*x+b (mod m)

        Encryption then follows mapping each symbol of the alphabet to
        the transformed alphabet

        >>> affine(B('cryptonita'), key=(9, 2))
        'uzkhrypwrc'

        The inverse makes the decryption:

        >>> affine(B('uzkhrypwrc'), key=(9, 2), dec=True)
        'cryptonita'

        If 'a' is not a coprime of 'm', the encryption/decryption
        may not work

        >>> key = (4, 0)  # with m=26, a=4 are not coprime (2 divides both)
        >>> ctext = affine(B('cryptonita'), key)
        >>> affine(ctext, key, dec=True)
        'pryptonvtn'

        References:
        https://en.wikipedia.org/wiki/Affine_cipher
        '''
    a, b = key
    m = len(alphabet)

    # see each symbol in the alphabet as a number starting
    # from 0 to m-1
    # then apply the affine transformation to each number
    idx = ((a * x + b) % m for x in range(m))

    # use the indexes to build a "shuffled" version of the
    # alphabet
    enc_alphabet = (alphabet[ix] for ix in idx)

    # with that, build the translation table
    tr = dict(
        zip(enc_alphabet, alphabet) if dec else zip(alphabet, enc_alphabet)
    )

    return substitute(ptext, tr)


def substitute(ptext, tr):
    return B(tr.get(p, p) for p in ptext)
