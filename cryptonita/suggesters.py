from cryptonita import B
from cryptonita.fuzzy_set import FuzzySet

def good_written_word_suggester(key, ciphertext, plaintext, speller):
    ''' See <plaintext> as a list of words and suggests for each
        misspelled one another word of the same length and compute
        the xor between the original word and the suggested.

        These xors are the patched needed to transform a word to the
        suggested one.

        Return a list of fuzzy set, one for each byte (not word)
        with the suggested patches.
        '''
    corrections = []
    for word in plaintext.split(b' '):
        word = B(word)
        wcorrections = [FuzzySet() for _ in range(len(word))]

        if speller.check(word):
            wsuggestions = [word]
        else:
            wsuggestions = (B(w) for w in speller.suggest(word) if len(w) == len(word))

        for wpatch in (word ^ s for s in wsuggestions):
            for sym_corrections, suggested_sym in zip(wcorrections, wpatch):
                sym_corrections[B(suggested_sym)] = 1

        corrections.extend(wcorrections)
        corrections.append(FuzzySet([B(0)]))   # the whitespace

    # the last is a spurious correction of a non-existent whitespace
    corrections.pop()
    assert len(corrections) == len(key)
    assert all(len(sym_corrections) >= 0 for sym_corrections in corrections)
    return corrections

