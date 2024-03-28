from cryptonita.deps import importdep

z3 = importdep('z3')

from cryptonita.helpers import are_same_length_or_fail, are_bytes_or_fail
'''
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.attacks.mapping import _ngrams_map
'''


def _single_ngram_map(mapping, _from, _to):
    ''' Asserts (in z3/smt terminology) that there is a mapping
        such maps <_from> to <_to>.

        Return this assertiong.
        '''
    are_same_length_or_fail(_from, _to)
    are_bytes_or_fail(_from, 'cipher-ngram')
    are_bytes_or_fail(_to, 'cipher-ngram')
    return z3.And([mapping[f] == t for f, t in zip(_from, _to)])


def _ngrams_map(possible_plain_ngrams_by_cipher_ngram, alphabet=None):
    ''' Let's assume that we are 100% sure that a particular ngram
        ('s') in the ciphertext is mapped to 'e' in the plaintext
        and that the 'c' is mapped to or 'a' or to 't'.

        In other words:

        >>> p1grams = {
        ...     b's': [b'e'],          # 100% sure
        ...     b'c': [b'a', b't'],    # 50%-50% sure
        ... }

        Let's assume also that we are 100% sure that the tri-gram
        'jds' in the ciphertext space maps to 'the' in the plaintext space

        >>> p3grams = {
        ...     b'jds': [b'the']
        ... }

        >>> alphabet = (0, 256)

        >>> p2grams = {}

        >>> possible_c2p_mappings = {}
        >>> possible_c2p_mappings.update(p1grams)
        >>> possible_c2p_mappings.update(p3grams)

        >>> #possible_plain_ngrams_by_cipher_ngram = UNION(p1grams, p2grams, p3grams)
        >>> #kmap = _ngrams_map(possible_plain_ngrams_by_cipher_ngram, alphabet)
        >>> kmap = _ngrams_map(possible_c2p_mappings, alphabet)
        '''

    if alphabet is None:
        alphabet = (0, 256)

    alph_low, alph_high = alphabet
    alph_sz = alph_high - alph_low

    kmap = z3.IntVector('kmap', alph_sz)
    assertions = []

    # Assert that every single item in the mapping (aka, every char)
    # is in the specified alphabet
    assertions.append(z3.And([km >= alph_low for km in kmap]))
    assertions.append(z3.And([km < alph_high for km in kmap]))

    for c, p_ngrams in possible_plain_ngrams_by_cipher_ngram.items():
        # Assert that the cipher ngram 'c' is mapped to one of its plain
        # ngram associated (p_grams).
        # In other words, we know that the decryption of 'c' is one of
        # the 'p' in 'p_grams' but we don't know which
        alternatives = z3.Or([_single_ngram_map(kmap, c, p) for p in p_ngrams])
        assertions.append(alternatives)

    return kmap
