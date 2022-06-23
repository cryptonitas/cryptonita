'''
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.metrics import *
'''

from cryptonita.helpers import are_same_length_or_fail


def count_coincidences(seq1, seq2=None, aligned=False):
    ''' Count how many coincidences are between <seq1> and <seq2>.

        >>> seq1 = B(b'AABC')
        >>> seq2 = B(b'EACAB')

        A coincidence can be seen as having the same value or symbol
        at the same position in both strings:

            AABC
            EACAB
             ^

        >>> count_coincidences(seq1, seq2, aligned=True)
        1

        But we can also see a coincidence if we shift or rotate one of
        the strings.

        For all the possible shifting or alignments we will find more
        coincidences:

            AABC    AABC    AABC    AABC    AABC
            EACAB   ACABE   CABEA   ABEAC   BEACA
             ^      ^        ^^     ^          ^

        >>> count_coincidences(seq1, seq2, aligned=False)
        6

        Other elements can be compared not only byte strings, as long
        as they support iteration and .freq() method.

        >>> ng1 = seq1.ngrams(2)
        >>> ng2 = seq2.ngrams(2)

            AA AB BC      AA AB BC      AA AB BC      AA AB BC
            EA AC CA AB   AC CA AB EA   CA AB EA AC   AB EA AC CA
                                           ^^

        >>> count_coincidences(ng1, ng2, aligned=False)
        1

        If the second input is not given, calculate the count of
        coincidences if <seq1> with itself. In this case <shift> *must* be True.

            AABC     AABC     AABC     AABC
            AABC     ABCA     BCAA     CAAB
         (not count) ^                  ^

        >>> count_coincidences(seq1)
        2

        >>> count_coincidences(seq1, aligned=True)
        <...>
        ValueError: Counting the coincidences of a sequence with itself and keep it aligned will always generate the same count, the length of the sequence.

        References:
        [1] https://eldipa.github.io/book-of-gehn/articles/2019/10/04/Index-of-Coincidence.html
    '''

    if seq2 is None:
        if aligned:
            raise ValueError(
                "Counting the coincidences of a sequence with itself and keep it aligned will always generate the same count, the length of the sequence."
            )
        else:
            f1 = seq1.freq()
            f2 = f1
            offset = 1
    else:
        if aligned:
            return sum(a == b for a, b in zip(seq1, seq2))
        else:
            f1 = seq1.freq()
            f2 = seq2.freq()
            offset = 0

    count = 0
    smaller, other = (f1, f2) if len(f1) < len(f2) else (f2, f1)
    for symbol, cnt in smaller.items():
        count += (cnt - offset) * other.get(symbol, 0)

    return count


def icoincidences(seq1, seq2=None, expected=None):
    r'''
        Take the sequence <seq1> that can be:
         - a ByteString
         - a Nblocks view
         - a Ngrams view
         - any other object that support SequenceStatsMixin.freq method.

        For the given sequence see how many items are repeated:
        count the coincidences; higher
        values means that the <seq1> is less random. [1]

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
            icoincidences(seq1, expected=e) == icoincidences(seq1) / e

        See equation 13 of [2] (in the paper, the value c is our 1/<expected>)

        Typically it comes from a theoretical "expected" value (1/256 for
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
    # The index of coincidence is meant to work over sequences of the same
    # length comparing them symbol by symbol (aligned)
    # If not seq2 is given, the index of coincidence computes the "auto" or "self"
    # version of the IC requiring obviously a non-alignment.
    if seq2 is not None:
        are_same_length_or_fail(seq1, seq2)
        aligned = True
    else:
        aligned = False

    # if seq2 is None, count_coincidences computes:
    #
    #     Sum for all i { (ni * (ni-1)) / (N * (N-1)) }
    #
    # otherwise count_coincidences computes:
    #
    #     Sum for all i { 1 if seq1[i] == seq2[i] else 0 }
    #
    counts = count_coincidences(seq1, seq2, aligned)

    # if seq2 is None, the counts are normalized by (N * (N-1))
    # otherwise by N
    norm = (len(seq1) * (len(seq1) - 1)) if seq2 is None else len(seq1)

    ic = counts / norm
    return ic if expected is None else ic / expected
