from cryptonita.fuzzy_set import FuzzySet
from cryptonita import B
from cryptonita.helpers import are_bytes_or_fail

from itertools import product, zip_longest

'''
>>> # Convenient definitions
>>> from cryptonita import B
>>> from cryptonita.attacks import brute_force, freq_attack, search  # byexample: +timeout=10

'''

def brute_force(ciphertext, score_func, key_space=1,
                        min_score=0):
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
            >>> brute_force(ciphertext, is_bmp, key_space=2)
            {'XY' -> 1.0000}

        Otherwise, <key_space> must be an iterable of bytes: each string of bytes
        is a key to try (we will try all of them in the given order)

            >>> ciphertext = B('\x1a\x15XXXY')
            >>> possible_keys = (B(k) for k in ('Q', 'X', 'Z'))
            >>> brute_force(ciphertext, is_bmp, key_space=possible_keys)
            {'X' -> 1.0000}

    '''
    assert 0.0 <= min_score <= 1.0
    are_bytes_or_fail(ciphertext, 'ciphertext')

    prob = {}
    if isinstance(key_space, int):
        key_space = (B(k) for k in product(range(256), repeat=key_space))

    elif isinstance(key_space, FuzzySet):
        prob = key_space

    keys = FuzzySet(((k, score_func(ciphertext ^ k.inf()) * prob.get(k, 1)) for k in key_space),
                        pr='tuple',
                        min_membership=min_score)
    return keys

def freq_attack(ciphertext, most_common_plain_ngrams, cipher_ngram_top=1):

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
    for N in (1,):
        # count all the possible ngrams of N bytes of length of
        # the ciphertext
        # then, pick the T most common and therefore the most likely to be
        # the encrypted version of the most common plain ngrams
        _cipher_ngrams = ciphertext.ngrams(N).most_common(T)

        # most common plain ngrams of N bytes of length
        _plain_ngrams = filter(lambda ngram: len(ngram) == N,
                                            most_common_plain_ngrams)

        # if our hypothesis is correct, at least one of the c cipher ngrams
        # will be (p ^ k) where p is one of the p plain ngrams
        # if this is true, one of the 'proposed keys' keys will be the real
        # secret key k
        #
        tmp = FuzzySet(((c ^ p, prob.get(p, 1)) for c, p in product(_cipher_ngrams,
                                                                    _plain_ngrams)),
                                pr='tuple')
        keys.update(tmp)

    return keys


def guess_key_length(ciphertext, length_space, score_func, min_score=0.5, **score_func_params):
    ''' Guess the length of the key that was used to cipher
        the given ciphertext.

        The possible lengths will be determined by <length_space>:
         - if it is a int, assume a range from 1 to <length_space>
         - otherwise, <length_space> needs to be an iterable of possible lengths

        For each possible length, score each one using <score_func> and
        drop anyone with a score of <min_score> or less.

        Extra parameters can be passed to the <score_func> using
        <score_func_params>.

        Return a FuzzySet with the lengths guessed.
        '''
    assert 0.0 <= min_score <= 1.0
    are_bytes_or_fail(ciphertext, 'ciphertext')

    if isinstance(length_space, int):
        length_space = range(1, length_space+1)

    params = score_func_params
    lengths = FuzzySet(((l, score_func(l, ciphertext, **params)) for l in length_space),
                        pr='tuple',
                        min_membership=min_score)
    return lengths


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

def search(start, stop, oracle, likely=None):
    ''' Search the first value in the range <start>:<stop>
        that statisfy the <oracle> condition.

        >>> def is_4(i):
        ...     print("%i == 4?" % i)
        ...     return i == 4

        >>> search(2, 10, is_4)
        2 == 4?
        3 == 4?
        4 == 4?
        4

        The <likely> optional parameter control from where the search
        should start. By default (<likely>==None), starts from
        the begin (<start>).

        But other values are possible like backward:

        >>> search(2, 10, is_4, likely='backward')
        9 == 4?
        8 == 4?
        7 == 4?
        6 == 4?
        5 == 4?
        4 == 4?
        4

        From the middle point (notice how the search expands from the
        middle to the extremes):

        >>> search(2, 10, is_4, likely='middle')
        6 == 4?
        5 == 4?
        7 == 4?
        4 == 4?
        4

        Or just from an arbitrary point:
        >>> search(2, 10, is_4, likely=8)
        8 == 4?
        7 == 4?
        9 == 4?
        6 == 4?
        5 == 4?
        4 == 4?
        4

    '''

    assert start <= stop
    if likely is None:
        likely = start
    elif likely == 'middle':
        likely = ((stop + start) // 2)
    elif likely == 'backward':
        likely = stop

    assert start <= likely <= stop

    lower  = range(likely-1, start-1, -1)
    higher = range(likely, stop)

    for i, j in zip_longest(higher, lower):
        if i is not None and oracle(i):
            return i

        if j is not None and oracle(j):
            return j

