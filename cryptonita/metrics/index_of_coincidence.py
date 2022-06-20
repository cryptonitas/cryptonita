'''
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.metrics.index_of_coincidence import *
'''


def count_coincidences(s1, s2=None, shift=True):
    ''' Count how many coincidences are between <s1> and <s2>.

        >>> s1 = B(b'AABC')
        >>> s2 = B(b'EACAB')

        A coincidence can be seen as having the same value or symbol
        at the same position in both strings:

            AABC
            EACAB
             ^

        >>> count_coincidences(s1, s2, shift=False)
        1

        But we can also see a coincidence if we shift or rotate one of
        the strings.

        For all the possible shifting or alignments we will find more
        coincidences:

            AABC    AABC    AABC    AABC    AABC
            EACAB   ACABE   CABEA   ABEAC   BEACA
             ^      ^        ^^     ^          ^

        >>> count_coincidences(s1, s2, shift=True)
        6

        Other elements can be compared not only byte strings, as long
        as they support iteration and .freq() method.

        >>> ng1 = s1.ngrams(2)
        >>> ng2 = s2.ngrams(2)

            AA AB BC      AA AB BC      AA AB BC      AA AB BC
            EA AC CA AB   AC CA AB EA   CA AB EA AC   AB EA AC CA
                                           ^^

        >>> count_coincidences(ng1, ng2, shift=True)
        1

        If the second input is not given, calculate the count of
        coincidences if <s1> with itself. In this case <shift> *must* be True.

            AABC     AABC     AABC     AABC
            AABC     ABCA     BCAA     CAAB
         (not count) ^                  ^

        >>> count_coincidences(s1)
        2

        >>> count_coincidences(s1, shift=False)
        <...>
        ValueError: We cannot calculate the auto count of coincidences without shifting.

        References:
        [1] https://eldipa.github.io/book-of-gehn/articles/2019/10/04/Index-of-Coincidence.html
    '''
    if not shift and s2 is None:
        raise ValueError(
            "We cannot calculate the auto count of coincidences without shifting."
        )

    if not shift:
        assert s2 is not None
        return sum(a == b for a, b in zip(s1, s2))

    elif s2 is None:
        f1 = s1.freq()

        count = 0
        for cnt in f1.values():
            count += cnt * (cnt - 1)

        return count

    else:
        f1 = s1.freq()
        f2 = s2.freq()

        count = 0
        smaller, other = (f1, f2) if len(f1) < len(f2) else (f2, f1)
        for symbol, cnt in smaller.items():
            count += cnt * other.get(symbol, 0)

        return count


def index_of_coincidence(s1, s2, expected):
    if expected < 1:
        # this is a probability, we can calculate the expected count
        # only if both inputs are of the same length
        if s2 is not None:
            are_same_length_or_fail(s1, s2)

        expected = expected * len(s1)

    return count_coincidences(s1, s2, shift=True) / expected
