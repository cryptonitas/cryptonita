import json
import math
import itertools
from collections import Counter

import scipy.stats as stats
import numpy as np
from langdetect import detect_langs

from cryptonita import B
from cryptonita.helpers import are_bytes_or_fail, are_same_length_or_fail

'''
>>> # Convenient definitions
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.scoring import *
>>> from cryptonita.scoring.freq import etaoin_shrdlu
'''

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

def all_in_alphabet(m, alphabet):
    ''' Score 1 if all the elements in the message <m> are in the <alphabet>.

        >>> alphabet = set(B(string.printable, encoding='ascii'))

        >>> message = B('hello world', encoding='ascii')
        >>> all_in_alphabet(message, alphabet)
        1

        Score with 0 otherwise

        >>> message = B('hello\x00world', encoding='ascii')
        >>> all_in_alphabet(message, alphabet)
        0

        If the <alphabet> is the sequence of all ASCII printable characters,
        use all_ascii_printable instead, it is faster.

        Use all_in_alphabet for 'custom' alphabets.
    '''

    are_bytes_or_fail(m, 'm')
    return 1 if len(set(m) - set(alphabet)) == 0 else 0

def fit_freq_score(m, expected_prob, return_p=False, significance=0.05):
    '''
        >>> expected_prob = etaoin_shrdlu()
        >>> fit_freq_score(B("These are not the droids you are looking for"),
        ...         expected_prob)
        0.5

        >>> fit_freq_score(B("7h353 4r3 n07 7h3 dr01d5 y0u 4r3 l00k1n6 f0r"),
        ...         expected_prob)
        0
    '''
    N = len(m)

    alphabet = [k for k in expected_prob]
    alphabet.sort()

    efreq = [expected_prob[k] * N for k in alphabet]

    ofreq = m.freq()
    ofreq = [ofreq.get(k, 0) for k in alphabet]

    # The "unexpected" events:
    # If the expected probabilities don't sum up to 1 (the expected freq
    # don't sum up to N), the missing prob/freq are for the "unexpected" events
    # Make sure it is a non-zero very low frequency
    _min = min(efreq) / 16
    efreq.append(max(_min, N-sum(efreq)))
    ofreq.append(N-sum(ofreq))  # the observed unexpected events can be zero

    x = np.arange(len(efreq))
    bins = [0]
    current_bin = 0
    for i in x:
        current_bin += efreq[i]
        if current_bin > 8:
            bins.append(i+1)
            current_bin = 0
    if current_bin > 0:
        bins.append(x[-1]+1)

    assert len(efreq) == len(ofreq) == len(x)

    ehist, bins = np.histogram(x, weights=efreq, bins=bins)
    ohist, _ = np.histogram(x, weights=ofreq, bins=bins)

    _, p = stats.chisquare(ohist, ehist)

    return p if return_p else (0 if p <= significance else 0.5)

def good_written_word_score(m, speller, word_weight_fun=len):
    wfun = (lambda w:1) if word_weight_fun is None else word_weight_fun
    words = m.split(sep=None)
    return sum(speller.check(w) * wfun(w) for w in words) / sum(wfun(w) for w in words)

def good_written_word_bit_score(m, speller):
    words = m.split(sep=None)
    score = 0
    for word in words:
        if speller.check(word):
            score += 1
        else:
            suggestions = speller.suggest(word)
            bit_length = len(word) * 8

            min_hamming_distance = bit_length
            w = B(word)
            for s in (s for s in suggestions if len(s) == len(word)):
                hd = w.hamming_distance(B(s).inf())
                if hd < min_hamming_distance:
                    min_hamming_distance = hd

            score += (bit_length - min_hamming_distance) / bit_length

    return score / len(words)

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

        It is related with icoincidences, but in the practice, entropy
        is slower and it is less discriminant.

        Nota bene: the entropy is calculated as:

            S = -sum(pk * log(pk))

        where pk is the frequency of the kth ngram and log is the natural
        logarithm (base e).

    '''
    return m.ngrams(N).entropy()

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

def icoincidences(seq, seq2=None, expected=None):
    r'''
        Take the sequence <seq> that can be:
         - a ByteString
         - a Nblocks view
         - a Ngrams view
         - any other object that support SequenceStatsMixin.freq method.

        For the given sequence see how many items are repeated:
        count the coincidences; higher
        values means that the <seq> is less random. [1]

        Mathematically,
            Sum for all i { (ni * (ni-1)) / (N * (N-1)) }

        where <ni> is the count of items <i> and <N> is the count of all the
        items seen.
        The result is a number between 0 (uniform random) and 1 (totally biased
        not random at all).

        For example, in the given file are 327 random strings. One of them
        is actually a message encrypted by doing a xor with a key of just 1 byte.
        Therefore, it should have more coincidences than the rest of the strings.

        >>> ciphertexts = open('test/ds/4.txt', 'rb').read().strip().split(b'\n')
        >>> ciphertexts = [B(c, encoding=16) for c in ciphertexts]

        >>> scores_and_indexes = [(icoincidences(c), i) \
        ...                         for i, c in enumerate(ciphertexts)]

        Remember, higher values are better

        >>> max(scores_and_indexes)
        (0.045977<...>, 170)

        Let's check if the 170th string is our ciphered message

        >>> key = B('5') # i am doing a little cheat here to speed up the things

        >>> ciphertexts[170] ^ key.inf()
        'Now that the party is jumping\n'

        If a second sequence <seq2> is provided, <icoincidences> will
        return the Index of Coincidence considering coincidences pair by pair

        Mathematically,
            Sum for all i { 1 if seq1[i] == seq2[i] else 0 } / N

            where <N> is the length of the sequence

        >>> icoincidences(ciphertexts[43], ciphertexts[12])
        0.033<...>

        >>> icoincidences(ciphertexts[12], ciphertexts[170])
        0.0

        In this mode, icoincidences gives an idea of how similar are
        the sequences. We can see that the non-random string (170th)
        is very different than the rest.

        The result is a number between 0 (very different) and 1 (identical)
        and it is a symmetric operation.

        If <expected> is given, the returned IC will be the *relative*
        IC respect with the <expected> probability of a coincidence.

        Mathematically,
            icoincidences(seq, expected=e) == icoincidences(seq) / e

        See equation 13 of [2] (in the paper, the value c is our 1/<expected>)

        Typically it comes from a theorical "expected" value (1/256 for
        a truly random sequence of bytes; 1/26 (0.0385) for a truly random
        sequence of letters of a 26-letters alphabet like the used in English)

        >>> 1/icoincidences(ciphertexts[12], expected=1/256)
        0.424<...>

        >>> icoincidences(ciphertexts[43], expected=1/256)
        0.588<...>

        >>> 1/icoincidences(ciphertexts[170], expected=1/256)
        0.0849<...>

        Note: because the relative IC can be any positive number, to
        compare those three I inverted the result if the number was greater
        than 1 making all of them between 0 and 1 and comparable.
        Notice how the relative IC of the 170th ciphertext is far from 1
        (random).

        We can do the same with the IC of two sequences:

        >>> icoincidences(ciphertexts[43], ciphertexts[12], expected=1/256)
        8.533<...>

        See the example 1 of [2] (in the paper, the value c is our 1/<expected>)

        The icoincidences function works over ngrams too:

        >>> icoincidences(ciphertexts[170].ngrams(2))
        0.0049<...>

        >>> icoincidences(ciphertexts[43].ngrams(2))
        0.0

        >>> icoincidences(ciphertexts[12].ngrams(2), ciphertexts[43].ngrams(2))
        0.0

        References:

        [1] Index of coincidence: https://en.wikipedia.org/wiki/Index_of_coincidence
        [2] The Index of Coincidence; Howard H Campaigne
        [3] Index of Coincidence Explained: https://eldipa.github.io/book-of-gehn/articles/2019/10/04/Index-of-Coincidence.html

    '''
    if seq2 is None:
        freqs = seq.freq().values()
        ic = sum(f * (f-1) for f in freqs) / (len(seq) * (len(seq) - 1))

    else:
        are_same_length_or_fail(seq, seq2)
        ic = sum(a == b for a, b in zip(seq, seq2)) / len(seq)

    return ic if expected is None else ic / expected

def ic_score(m, m2):
    return icoincidences(m, m2)


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

    distance = B(ciphertext[:l]).hamming_distance(B(ciphertext[l:l*2]))
    return 1 - (distance / (l*8))


def key_length_by_ic(length, ciphertext):
    ''' Score the possible <length> of the key that was used to encrypt
        and obtain the <ciphertext> using the Index of Coincidence (IC).

        Pick bytes from <ciphertext> that are <length> bytes of distance:
            1, l, 2l, ...

        and compute the IC.
        '''
    return icoincidences(B(ciphertext[::length]))


# (b - a + 1)**2 - 1 / 12  = (b==1, a==0) -> 3/12
# Chebyshev's_inequality

# P [ |X - u| >= kd ] <= 1/k**2    (u = mean, d = sqrt(variance), k >= 1, X random variable)
# P [ |X - u| >= a ]  <= v / a**2  (v = var, a >= 1)
