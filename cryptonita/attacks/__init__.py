from cryptonita.fuzzy_set import FuzzySet
from cryptonita import B
from cryptonita.helpers import are_bytes_or_fail

from itertools import product, zip_longest, islice
from operator import xor
'''
>>> # Convenient definitions
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.attacks import brute_force, freq_attack, search  # byexample: +timeout=10
>>> from cryptonita.fuzzy_set import FuzzySet  # byexample: +timeout=1
'''


def brute_force(ciphertext, score_func, key_space=1, min_score=0):
    r'''Guess what key was used to xor the <ciphertext>.
        Guessing means try every single possible key so we need to score
        each try with <score_func> to see what key is really useful.

        For example, if we know that the plaintext is a Bitmap image
        we can score a decrypted message like:

            >>> def is_bmp(m):
            ...     return 1 if m[:2] == b"BM" else 0

        because all the Bitmap images starts with the magic bytes 'BM'.

        Then, we guess the key:

            >>> ciphertext = B('\x1a\x15XXXY')
            >>> guessed_keys = brute_force(ciphertext, is_bmp)

            >>> guessed_keys
            {'X' -> 1.0000}


        Not always the guess is perfect. Because of this we return a FuzzySet
        object that each guessed key with its likehood.

        If <key_space> is an integer, the key space is all possible
        keys of <key_space> bytes.
        It is advised to keep <key_space> less than 3... may be 4.
        Also, use <min_score> to drop all the keys with score less than
        <min_score> to keep the memory usage at minumum.

            >>> ciphertext = B('\x1a\x14XYXX')
            >>> brute_force(ciphertext, is_bmp, key_space=2)    # byexample: +timeout=10
            {'XY' -> 1.0000}

        Otherwise, <key_space> must be an iterable of bytes: each string of bytes
        is a key to try (we will try all of them in the given order)

            >>> ciphertext = B('\x1a\x15XXXY')
            >>> possible_keys = (B(k) for k in ('Q', 'X', 'Z'))
            >>> brute_force(ciphertext, is_bmp, key_space=possible_keys)
            {'X' -> 1.0000}

        When <key_space> is a FuzzySet, not only each member is tested
        as a possible key to decipher the given <ciphertext> but also
        the likehood of the member scales the score.

        In this example the score of 1 (from is_bmp) is multiplied by the
        correct key's likehood 0.5 (from the FuzzySet):

            >>> ciphertext = B('\x1a\x15XXXY')
            >>> possible_keys = FuzzySet({B(k) : 0.5 for k in ('Q', 'X', 'Z')})
            >>> brute_force(ciphertext, is_bmp, key_space=possible_keys)
            {'X' -> 0.5000}


    '''
    assert 0.0 <= min_score <= 1.0
    are_bytes_or_fail(ciphertext, 'ciphertext')

    prob = {}
    if isinstance(key_space, int):
        key_space = (B(k) for k in product(range(256), repeat=key_space))

    elif isinstance(key_space, FuzzySet):
        prob = key_space

    key_and_likehood = (
        (k, score_func(ciphertext ^ k.inf()) * prob.get(k, 1))
        for k in key_space
    )
    keys = FuzzySet(key_and_likehood, pr='tuple', min_membership=min_score)
    return keys


def freq_attack(
    ciphertext, most_common_plain_ngrams, cipher_ngram_top=1, op=xor
):
    r'''Try to break the ciphering doing a frequency attack.
        The idea is that the plain text has some ngrams more frequent than
        others and that is reflected in the <ciphertext>.

        Then, we can assume that at least one of the <cipher_ngram_top> most
        common cipher ngrams is one of the <most_common_plain_ngrams> encrypted
        with the secret key.

        >>> most_common_plain_ngrams = [B(b) for b in b'etaoin shrdlu']
        >>> cipher_ngram_top = 1

        So, for all the most common plain ngrams p and cipher ngrams c we can
        propose (c ^ p) = k.

        >>> ciphertext = B('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736',
        ...                     encoding=16)

        >>> proposed_keys = freq_attack(ciphertext, most_common_plain_ngrams)

        >>> proposed_keys       # byexample: +norm-ws +geometry=24x400
        {<...>'X' -> 1.000<...>}


        Then we can use them to guess the secret key

        >>> from cryptonita.scoring import all_ascii_printable
        >>> key = brute_force(ciphertext, key_space=proposed_keys.keys(),
        ...                 score_func=all_ascii_printable).most_likely()

        And decrypt the message

        >>> ciphertext ^ key.inf()
        "Cooking MC's like a pound of bacon"

        Nice reading: http://norvig.com/mayzner.html
    '''

    # aliases
    T = cipher_ngram_top

    are_bytes_or_fail(ciphertext, 'ciphertext')

    keys = FuzzySet()

    prob = {}
    if isinstance(most_common_plain_ngrams, FuzzySet):
        prob = most_common_plain_ngrams

    # XXX despite the code supports different values of N in the same
    # run, that is, we support do an freq attack using ngrams of different
    # lengths, it is not clear how we should merge the results.
    #
    # Using ngrams of length 1, we can propose keys of 1 byte. If we use
    # ngrams of length 2, we can propose keys of 2 bytes.
    #
    # Now, if we have propose keys of 1 and 2 bytes how we merge them?
    # If the real secret key is of 1 byte, we should discard all the proposed
    # keys of 2 bytes that don't have those 2 bytes equals.
    #
    # Then, we will have a proposed key X (1 byte) and a proposed key XX (2 bytes)
    # but they are the same. So should we remove them too?
    # But if we do, we removed all the proposed keys of 2 bytes, what was the
    # point? It will only be useful if we don't find X but XX or we don't find XX
    # and we do find X.
    for N in (1, ):
        # count all the possible ngrams of N bytes of length of
        # the ciphertext
        # then, pick the T most common and therefore the most likely to be
        # the encrypted version of the most common plain ngrams
        _cipher_ngrams = ciphertext.ngrams(N).most_common(T)

        # most common plain ngrams of N bytes of length
        _plain_ngrams = filter(
            lambda ngram: len(ngram) == N, most_common_plain_ngrams
        )

        # if our hypothesis is correct, at least one of the c cipher ngrams
        # will be (p ^ k) where p is one of the p plain ngrams
        # if this is true, one of the 'proposed keys' keys will be the real
        # secret key k
        tmp = FuzzySet(
            (
                (op(c, p), prob.get(p, 1))
                for c, p in product(_cipher_ngrams, _plain_ngrams)
            ),
            pr='tuple'
        )
        keys.update(tmp)

    return keys


def correct_key(key, ciphertexts, suggester):
    ''' Use <key> to decrypt each <ciphertext> and for each plaintext
        try to correct the <key> to improve the quality of the plaintexts
        using the corrections suggested by <suggester>.

        Return a list of possible bytes, one for each key.
        '''
    corrections = [FuzzySet() for _ in range(len(key))]
    for ctext in ciphertexts:
        ptext = ctext[:len(key)] ^ key
        tmp = suggester(key, ctext, ptext)
        for sym_corrections, new_sym_corrections in zip(corrections, tmp):
            new_sym_corrections.normalize()
            sym_corrections |= new_sym_corrections
            sym_corrections.normalize()

    assert all(len(sym_corrections) >= 0 for sym_corrections in corrections)
    return corrections


def search(space, oracle, cnt=1, default=None):
    ''' Search the first value in the <space>
        that statisfy the <oracle> condition.

        >>> def is_4(i):
        ...     print("%i == 4?" % i)
        ...     return i == 4

        >>> search(range(2, 5), is_4)
        2 == 4?
        3 == 4?
        4 == 4?
        4

        The <space> can be any generator / iterator / sequence
        (anything that supports __iter__).

        From cryptonita.space you can find some specialized space
        definitions.

        For example, IntSpace is simil to Python's range() but
        support arbitrary starting points so you can explore
        a range of integers from the middle to the extremes.

        >>> from cryptonita.space import IntSpace

        >>> search(IntSpace(2, 10, start='middle'), is_4)
        6 == 4?
        5 == 4?
        7 == 4?
        4 == 4?
        4

        >>> search(IntSpace(2, 10, start=8), is_4)
        8 == 4?
        7 == 4?
        9 == 4?
        6 == 4?
        10 == 4?
        5 == 4?
        4 == 4?
        4

        >>> search(IntSpace(2, 10, start='end'), is_4)
        10 == 4?
        9 == 4?
        8 == 4?
        7 == 4?
        6 == 4?
        5 == 4?
        4 == 4?
        4

        With <cnt> you can control how many elements are returned (1 by default).
        The return is an iterator

        >>> def is_even(i):
        ...     print("is %i even?" % i)
        ...     return i % 2 == 0

        >>> list(search(range(10), is_even, cnt=3))
        is 0 even?
        is 1 even?
        is 2 even?
        is 3 even?
        is 4 even?
        [0, 2, 4]

        The special value `all` can be used to do a full exploration
        of the space:

        >>> list(search(range(10), is_even, cnt='all'))
        <...>
        [0, 2, 4, 6, 8]
    '''

    # TODO: add limits to search like max count of elements to explore
    # or time to do the search.
    # Can be the search paused and restored later? pickled/serialized?
    if cnt == 1:
        return next((s for s in space if oracle(s)), default)

    elif isinstance(cnt, int):
        if cnt <= 0:
            raise ValueError(
                f"Count of elements to search must be positive but {cnt} was found."
            )

        return islice((s for s in space if oracle(s)), cnt)

    elif isinstance(cnt, str):
        if cnt != 'all':
            raise ValueError(
                f"Unexpected count '{cnt}'. Accepted values are: 'all'."
            )

        return (s for s in space if oracle(s))
