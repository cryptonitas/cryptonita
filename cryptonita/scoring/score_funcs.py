import json
import math
import itertools
from collections import Counter

from cryptonita.deps import importdep

np = importdep('numpy')
stats = importdep('scipy.stats')
detect_langs = importdep('language.detect_langs')

from cryptonita import B
from cryptonita.helpers import are_bytes_or_fail, are_same_length_or_fail
from cryptonita.metrics import icoincidences
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
    efreq.append(max(_min, N - sum(efreq)))
    ofreq.append(N - sum(ofreq))  # the observed unexpected events can be zero

    x = np.arange(len(efreq))
    bins = [0]
    current_bin = 0
    for i in x:
        current_bin += efreq[i]
        if current_bin > 8:
            bins.append(i + 1)
            current_bin = 0
    if current_bin > 0:
        bins.append(x[-1] + 1)

    assert len(efreq) == len(ofreq) == len(x)

    ehist, bins = np.histogram(x, weights=efreq, bins=bins)
    ohist, _ = np.histogram(x, weights=ofreq, bins=bins)

    _, p = stats.chisquare(ohist, ehist)

    return p if return_p else (0 if p <= significance else 0.5)


def good_written_word_score(m, speller, word_weight_fun=len):
    wfun = (lambda w: 1) if word_weight_fun is None else word_weight_fun
    words = m.split(sep=None)
    return sum(speller.check(w) * wfun(w)
               for w in words) / sum(wfun(w) for w in words)


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


def ic_score(m, m2):
    return icoincidences(m, m2)


def key_length_by_hamming_distance(ciphertext, length):
    ''' Score how much likely is <length> to be the length of the key
        which was used to encrypt and obtain the ciphertext (for a xor cipher)

        This estimate is done using the hamming distance.

        If K is a random uniform distributed key space, k one key from that
        space and ki and kj two bytes of that key where they are l bytes
        separated between.

        In other words:

            ki = k[x]
            kj = k[x+l]

        For the ci and cj ciphertext bytes we have:

            pi = ci ^ ki   and   pj = cj ^ kj

        then, the hamming distance will be:

            h(ci, cj) = sum_1s((pi ^ ki) ^ (pj ^ kj))
                      = sum_1s((pi ^ pj) ^ (ki ^ kj))

        When ki != kj, then ki ^ kj is a random uniform distributed byte so
        (pi ^ pj) ^ (ki ^ kj) is also a random uniform distributed byte
        and the expected count of 1s is half (4 bits for a 8-bits byte)

        Consider now that we are in the lucky case of ki == kj,
        the hamming distance will be:

            h(ci, cj) = sum_1s((pi ^ pj))

        If we assume the plaintext space is *not* uniform distributed,
        so the count of 1s of pi ^ pj will be significantly smaller
        than 4 so the hamming distance will be smaller than 4.

        In other words, assuming that the plaintext is *not* uniform,
        pi and pj are similar.

        This will indicate that we chosen ki and kj such they are the same,
        so indeed we found a candidate length for the secret k.

        As stated before, this length estimation assumes two things:
         - K is a random uniform distributed key string
         - P is *not* a random uniform distributed plaintext string.

        If K is not a random uniform distributed key space, the hamming
        distance may not be the best discriminant.
        '''

    l = length
    if len(ciphertext) < l * 2:
        raise ValueError(
            "The ciphertext is too short to guess the key's length and it is impossible to see if a key of %i bytes could be possible."
            % l
        )

    # This computes how many bits differ between two consecutive
    # blocks of length l
    # Keep the maximum difference
    max_distance = 0
    cblocks = ciphertext.nblocks(l)
    for a, b in zip(cblocks[:-1], cblocks[1:]):
        if len(b) < l:
            # this may happen if the original ciphertext has a total length
            # not divisible by l, so the last block will have less bytes
            # In that case we discard it
            break

        max_distance = max(a.hamming_distance(b), max_distance)

    # Compute the score normalizing the distance
    return 1 - (max_distance / (l * 8))


def key_length_by_ic(ciphertext, length):
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
