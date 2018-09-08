import json
import math
import itertools
from collections import Counter

import scipy.stats as stats
from langdetect import detect_langs

from cryptonita.bytestring import B, are_bytes_or_fail

'''
>>> # Convenient definitions
>>> from cryptonita.bytestring import B
>>> from cryptonita.scoring import *

'''


def hamming_distance(m1, m2):
    r'''
        Return the Hamming distance between <m1> and <m2>.

        >>> m1 = B('this is a test')
        >>> m2 = B('wokka wokka!!!')

        >>> hamming_distance(m1, m2)
        37

        The Hamming (or edit) distance is the count of how many bits
        these two string differ. It is defined for strings of the same
        lengths, so the following will fail:

        >>> hamming_distance(m1, m1 + m1)
        Traceback (most recent call last):
        <...>
        ValueError: Mismatch lengths. Left string has 14 bytes but right string has 28.

    '''

    x = m1 ^ m2
    return x.count_1s()

def all_ascii_printable(m):
    ''' Score with 1 if the message has only ASCII printable characters.

            >>> import string

            >>> message = B(string.printable, encoding='ascii')
            >>> all_ascii_printable(message)
            1

        Score with 0 otherwise

            >>> message = B(string.printable + "\x04", encoding='ascii')
            >>> all_ascii_printable(message)
            0

    '''
    are_bytes_or_fail(m, 'm')
    return 1 if all((32 <= b <= 126 or 9 <= b <= 13) for b in m) else 0

def is_language(m, language):
    return detect_langs(m)[language]

def ngram_entropy_score(m, N=1):
    r'''
        Take the frequency of each ngram of <N> bytes of length from
        <m>, and estimate the entropy.

        >>> truly_random = B('3nQucdIjAbP1n8wZ7c+xs4KoRPo6U1GP3jJllAzU24rYiCo6' +\
        ...                  'ZOgWt/zq5nG0XyNKPO95dBytg90rXxGDJGzRCNhiFX9GLZgV' +\
        ...                  'NKxbbbvrZ3bBc1b6TcthBvMWYvGAkdmOeR/TDaJgd0/x5nt5' +\
        ...                  'SiZ7Aq1+n2Eood2LxCLYCiytrp8=', encoding=64)

        >>> ngram_entropy_score(truly_random, N=1)
        4.55<...>

        Lower values are associated with string less random.

        >>> no_random = B([0b001, 0b010, 0b110, 0b001] * 64)
        >>> ngram_entropy_score(no_random, N=1)
        1.039<...>

        It is quite useful to distinguish short random sequences from not-much
        random sequences.

        It is related with index_of_coincidence, but in the practice, entropy
        is slower and it is less discriminant.

        Nota bene: the entropy is calculated as:

            S = -sum(pk * log(pk))

        where pk is the frequency of the kth ngram and log is the natural
        logarithm (base e).

    '''
    freq = list(m.ngrams(N).freq().values())
    return stats.entropy(freq)

def yes_no_score(m, yes_prob=0.5):
    r'''
        Count how many 1s (yes or successes) the <m> strings has (a byte
        string that it will be seing like a string of bits).

        Then, under the hypothesis of that the sequence <m> is a Bernulli
        process (a random uniform string), <yes_prob> is the hypothetical
        probability of yes or success.

        >>> truly_random = B('3nQucdIjAbP1n8wZ7c+xs4KoRPo6U1GP3jJllAzU24rYiCo6' +\
        ...                  'ZOgWt/zq5nG0XyNKPO95dBytg90rXxGDJGzRCNhiFX9GLZgV' +\
        ...                  'NKxbbbvrZ3bBc1b6TcthBvMWYvGAkdmOeR/TDaJgd0/x5nt5' +\
        ...                  'SiZ7Aq1+n2Eood2LxCLYCiytrp8=', encoding=64)

        Under this hypothetical (named the null hypothesis), return the
        probability of *reject* the hypothesis.

        >>> yes_no_score(truly_random, yes_prob=0.5)
        0.488<...>

        The value returned is the probability of reject the hypothesis or
        the p-value [1].

        Even if the p-value is really small so we cannot reject the hypothesis,
        we *cannot* say then that <m> *is* truly uniformely random;
        We *only* can say that we don't have evidence to *reject*
        the hypothesis.

        Only high values allow us to reject the hypothesis, nothing else.

        >>> no_random = B([0b001, 0b010, 0b110, 0b001] * 64)
        >>> yes_no_score(no_random, yes_prob=0.5)
        1.0

        [The p-value] "does not tell us what we want to know,
        and we so much want to know what we want to know that,
        out of desperation, we nevertheless believe that it does"
                                                        (Cohen, 1994).

        References:

        [1] p-value: https://en.wikipedia.org/wiki/P-value
        [2] binomial test: https://en.wikipedia.org/wiki/Binomial_test
    '''

    sucessess = m.count_1s()
    bits = len(m) * 8

    return 1 - stats.binom_test(sucessess, n=bits)

def index_of_coincidence(m, N=1, mode='ngrams'):
    r'''
        Take the string of bytes <m> and see it as a sequence of ngrams
        of length <N> if <mode> is 'ngrams' or see it as a sequence of
        non-overlaping blocks of length <N> if <mode> is 'nblocks'.

        Then, see how many ngrams are repeated: count the coincidences; higher
        values means that the <m> sequence is less random. [1]

        For example, in the given file are 327 random strings. One of them
        is actually a message encrypted by doing a xor with a key of just 1 byte.
        Therefore, it should have more coincidences than the rest of the strings.

        >>> ciphertexts = open('data/4.txt', 'rb').read().strip().split(b'\n')
        >>> ciphertexts = [B(c, encoding=16) for c in ciphertexts]

        >>> scores_and_indexes = [(index_of_coincidence(c), i) \
        ...                         for i, c in enumerate(ciphertexts)]

        Remember, higher values are better

        >>> max(scores_and_indexes)
        (0.045977<...>, 170)

        Let's check if the 170th string is our ciphered message

        >>> key = B('5') # i am doing a little cheat here to speed up the things

        >>> ciphertexts[170] ^ key.inf()
        'Now that the party is jumping\n'

        References:

        [1] Index of coincidence: https://en.wikipedia.org/wiki/Index_of_coincidence

    '''
    if mode == 'ngrams':
        seq = m.ngrams(N)
    elif mode == 'nblocks':
        seq = m.nblocks(N)
    else:
        raise ValueError("Unknow mode %s" % mode)

    freqs = seq.freq().values()
    text_len = len(m) - N + 1
    # TODO talk about why the c factor should not be used:
    # - it makes the final number a non-prob value (greather than 1)
    # - it is just a scalar factor to separate one value from the other but
    #   this is a human invention, the machine has no problem to see the
    #   difference of 0.0001 and 0.000011.
    return sum(f * (f-1) for f in freqs) / (text_len * (text_len - 1))


def count_duplicated_blocks(s, block_size, distance=None, indexes=False):
    r'''Count how many blocks are repeated or duplicated.

            >>> s = B('AABBAACCCCDDAADDAA')
            >>> count_duplicated_blocks(s, block_size=2)
            5

        If the <distance> parameter is given, a block is considered
        duplicated if another block is the same *and* it is <distance>
        blocks of distance.

        <distance> equal to 0 means "two consecutive blocks"

            >>> # the CCs
            >>> count_duplicated_blocks(s, block_size=2, distance=0)
            1

            >>> # the first 2 and last 2 AAs and the DDs
            >>> count_duplicated_blocks(s, block_size=2, distance=1)
            3

            >>> # the first 2 AAs with the last 2 AAs
            >>> count_duplicated_blocks(s, block_size=2, distance=5)
            2

    '''
    # TODO i'm not resistent to possible false positive!
    blocks = list(s.nblocks(block_size))

    if distance is not None:
        # consecutive blocks if distance is 0
        # 1 block between if distance is 1, ...
        pairs = zip(blocks[:-1-distance], blocks[1+distance:])

        count = 0
        for a, b in pairs:
            if a == b:
                count += 1

        return count

    else:
        # count any duplicated block, no matter how far is it from
        # its copy
        before = len(blocks)
        after  = len(set(blocks))

        return before - after

def key_length_by_hamming_distance(length, ciphertext):
    ''' Score how much likely is <length> to be the length of the key
        which was used to encrypt and obtain the ciphertext.

        This estimate is done using the hamming distance.

        If K is a random uniform distributed key space, k one key from that
        space and ki and kj two bytes of that key.

        For the ci and cj ciphertext bytes we have:
            pi = ci ^ ki   and   pj = cj ^ kj

        then, the hamming distance will be:

            h(ci, cj) = sum_1s((pi ^ ki) ^ (pj ^ kj))
                      = sum_1s((pi ^ pj) ^ (ki ^ kj))

        now if ki == kj, the hamming distance will be

            h(ci, cj) = sum_1s((pi ^ pj))

        If the plaintext space is *not* uniform distributed, the count of 1s
        of pi ^ pj will be smaller (pi and pj are similar)

        If ki != kj, then ki ^ kj is a random uniform distributed byte so
          (pi ^ pj) ^ (ki ^ kj) is also a random uniform distributed byte
        and the expected count of 1s is half (4 bits for a 8-bits byte)

        With this we can discriminate when ki == kj or not

        However this assumes two thing:
         - K is a random uniform distributed key string
         - P is *not* a random uniform distributed plaintext string.

        If K is not a random uniform distributed key space, the hamming
        distance may not be the best discriminant.
        '''

    l = length
    if len(ciphertext) < l * 2:
        raise ValueError("The ciphertext is too short to guess the key's length and it is impossible to see if a key of %i bytes could be possible." % l)

    distance = hamming_distance(B(ciphertext[:l]), B(ciphertext[l:l*2]))
    return 1 - (distance / (l*8))


def key_length_by_ic(length, ciphertext, N=1):
    ''' Score the possible <length> of the key that was used to encrypt
        and obtain the <ciphertext> using the Index of Coincidence (IC).

        Pick bytes from <ciphertext> that are <length> bytes of distance:
            1, l, 2l, ...

        and compute the IC.
        '''
    return index_of_coincidence(B(ciphertext[::length]), N)


# (b - a + 1)**2 - 1 / 12  = (b==1, a==0) -> 3/12
# Chebyshev's_inequality

# P [ |X - u| >= kd ] <= 1/k**2    (u = mean, d = sqrt(variance), k >= 1, X random variable)
# P [ |X - u| >= a ]  <= v / a**2  (v = var, a >= 1)
