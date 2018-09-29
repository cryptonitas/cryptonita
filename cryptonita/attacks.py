import cryptonita.scoring as scoring
from cryptonita.fuzzy_set import FuzzySet
from cryptonita.bytestring import B, are_bytes_or_fail

from itertools import product

'''
>>> # Convenient definitions
>>> from cryptonita.bytestring import B
>>> from cryptonita.attacks import brute_force, freq_attack  # byexample: +timeout=10

'''

def brute_force(ciphertext, score_func, key_space=1,
                        min_score=0.25):
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

        >>> proposed_keys       # byexample: +norm-ws
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

        # if our hypthesis is correct, at least one of the c cipher ngrams
        # will be (p ^ k) where p is one of the p plain ngrams
        # if this is true, one of the 'proposed keys' keys will be the real
        # secret key k
        #
        tmp = FuzzySet(((c ^ p, prob.get(p, 1)) for c, p in product(_cipher_ngrams,
                                                                    _plain_ngrams)),
                                pr='tuple')
        keys.update(tmp)

    return keys

def decrypt_ecb_tail(alignment, block_size, encryption_oracle, limit=None):
    align_test_block = B("A" * alignment)

    test_block = B("A" * (block_size - 1))
    align_target_block = B(test_block) # copy
    distance = 0

    decrypted_bytes = []
    i = 0
    eof = False
    while not eof and (i < limit if limit else True):
        i += 1
        eof = True
        for b in range(256):
            b = B(b)

            # propose the following choosen plaintext:
            #
            #   |-------|-------|-------|------
            #    ....AAA AAAAAAb AAAAAA? .....
            #       |       |       |
            #       |       |  a block identical to the test block except
            #       |       |  the last byte that's unknow to us (to be decypted)
            #       |  a "test" block: a full block where the last byte
            #       |  is our guessed byte (if 'b' is equal to '?' our guess is correct)
            #    padding block for alignment purposes
            tmp = align_test_block + test_block + b + align_target_block
            c = encryption_oracle(tmp)

            # TODO i'm not resistent to possible false positive!
            if c.nblocks(block_size).has_duplicates(distance):
                # two block had collided to a <distance> blocks of distance
                # that means that out guess 'b' matched with the unknow
                # bytes '?' effectively decrypting it
                eof = False
                decrypted_bytes.append(b)

                # the test block shift to the left one byte, now that we
                # now that 'b' is the correct byte we are reserving one byte
                # on the right for the next guess
                #           |-------|
                #            AAAAAAb  -> b is guessed ok (G)
                #           |-------|
                #            AAAAAAG  -> shift the block to make room
                #           |-------|
                #            AAAAAG   -> the byte missing will be filled
                #                        with the next guess 'b'
                test_block = test_block << b

                if len(align_target_block) == 0:
                    align_target_block = B("A" * (block_size - 1))
                    distance += 1
                else:
                    align_target_block = align_target_block[:-1]

                break

    return B(b''.join(decrypted_bytes))

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

