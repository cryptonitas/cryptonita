'''
>>> from cryptonita.conv import B           # byexample: +timeout=10
>>> from cryptonita.metrics.kasiski import *
'''

from cryptonita.conv import B
from bisect import bisect_left

from collections import Counter

def as_3ngram_repeated_positions(s):
    ''' Given a string of bytes return a sorted list
        of (ngram, postions) tuples.

        Each tuple consist in a 3-ngram from the byte string
        and a list of 2 or more positions where the ngram
        can be found in the original byte string.

        >>> s = B(b'ABCDBCDABCDBC')
        >>> as_3ngram_repeated_positions(s)
        [('ABC', [0, 7]), ('BCD', [1, 4, 8]), ('CDB', [2, 9]), ('DBC', [3, 10])]
        '''
    # create a dict that maps a 3-ngram to it position or positions
    # Time/Space O(n)
    pos_by_ngram = {}
    for ix, ngram in enumerate(s.ngrams(3)):
        try:
            pos_by_ngram[ngram].append(ix)
        except KeyError:
            pos_by_ngram[ngram] = [ix]

    # filter out any unique ngram (leave only the ngrams
    # that have 2 or more positions)
    # Time/Space O(n)
    tmp = {}
    for ngram, positions in pos_by_ngram.items():
        if len(positions) >= 2:
            tmp[ngram] = positions

    pos_by_ngram = tmp

    # same but as a sorted list: O(n logn)
    return list(sorted(pos_by_ngram.items()))

def ordered_positions_intersections(a, b):
    ''' Given two ordered list <a> and <b>, return
        an ordered list with the numbers that both
        list have in common.

        >>> ordered_positions_intersections([1, 3, 4, 5], [2, 3, 5, 6])
        [3, 5]

        >>> ordered_positions_intersections([1, 4, 5], [2, 3, 5, 6])
        [5]

        >>> ordered_positions_intersections([1, 5, 9], [2, 3, 5, 6])
        [5]

        >>> ordered_positions_intersections([1, 9], [2, 3, 5, 6])
        []
        '''

    i, j = 0, 0
    res = []
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            res.append(a[i])
            i += 1
            j += 1
        elif a[i] < b[j]:
            i += 1
        else:
            j += 1

    return res

def merge_overlaping(ngram_pos_list):
    '''
        Given a ordered list of tuples (ngram, positions)
        where all the ngrams have N bytes, create another
        ordered list of the same tuples where the ngrams
        are of N+1 bytes.

        The idea is that two ngrams G1 and G2 of N bytes at positions
        P1 and P2 can be merged if they share the same suffix/prefix
        (aka G1[1:] == G2[:-1]) *and* are at the same position shifted
        by on (aka P1 + 1 == P2)

        >>> #       0123456789ABC
        >>> s = B(b'ABCDBCDABCDBC')
        >>> l3 = as_3ngram_repeated_positions(s)
        >>> l3
        [('ABC', [0, 7]), ('BCD', [1, 4, 8]), ('CDB', [2, 9]), ('DBC', [3, 10])]

        >>> l4 = merge_overlaping(l3)
        >>> l4
        [('ABCD', [0, 7]), ('BCDB', [1, 8]), ('CDBC', [2, 9])]

        >>> l5 = merge_overlaping(l4)
        >>> l5
        [('ABCDB', [0, 7]), ('BCDBC', [1, 8])]

        >>> l6 = merge_overlaping(l5)
        >>> l6
        [('ABCDBC', [0, 7])]

        >>> l7 = merge_overlaping(l6)
        >>> l7
        []
        '''
    res = []
    for target in ngram_pos_list:
        tngram, tpositions = target

        # if our target is ABC at the positions 0, 4, 8
        # we want to find all the ngrams that have as prefix
        # the BC suffix: BC0, BC1, BC2, ...
        # if those ngrams exist and are in a +1 positions respect
        # the positions of our target then it means that those
        # share the same space and therefore can be merged into
        # ngrams larger (they overlap)
        #
        #  initial: ABC at 0, BCD at 1, BCD at 8
        #
        #  target = ABC, prefix = BC, position+1 = 0+1
        #
        #  does exist BC0? no
        #  does exist BC1? no
        #        :::
        #  does exist BCD? yes, at positions 1 and 8
        #   does it at the 1 position? yes,
        #       then the ABC at the position 0 and the BCD
        #       at the position 1 are sharing the same place
        #       there is an ABCD at the position 0

        tpositions_plus_1 = [p+1 for p in tpositions]
        prefix = tngram[1:]

        # search for candidates: if our target is ABC, the prefix
        # is BC and the candidates are all the 3-ngrams that
        # have a 2-ngram prefix of BC. In other words BC0, BC1, BC2
        # and so on are candidates
        first = prefix + B(b'\x00')    # literally BCD0

        # first candidate's index, if any
        ix = bisect_left(ngram_pos_list, (first, []))
        L = len(ngram_pos_list)
        while ix < L:
            candidate = ngram_pos_list[ix]
            if not candidate[0].startswith(prefix):
                # this is not a candidate and because the list
                # is sorted this means that we ran out of candidates
                break

            # check the positions of our target+1 and the candidate's one
            # and see if there is a coincidence
            shared_positions = ordered_positions_intersections(tpositions_plus_1, candidate[1])

            if len(shared_positions) <= 1:
                # the ngrams do not overlap, continue
                break

            # found!
            merged_ngram = tngram + candidate[0][-1:]
            assert(len(merged_ngram) == len(tngram) + 1)

            merged_at_positions = [p-1 for p in shared_positions]

            # because we are iteration over ngram_pos_list that it is sorted
            # our result list will stay sorted
            res.append((merged_ngram, merged_at_positions))

            ix += 1

    return res

def deltas_from_positions(positions):
    '''
        Return the difference between the positions.

        >>> deltas_from_positions([0, 7])
        [7]

        >>> deltas_from_positions([1, 4, 8])
        [3, 7, 4]

        >>> deltas_from_positions([1, 4, 7, 11])
        [3, 6, 10, 3, 7, 4]
    '''
    assert len(positions) >= 2

    res = []
    for i in range(len(positions)-1):
        ref = positions[i]
        for j in range(i+1, len(positions)):
            res.append(positions[j] - ref)

    return res


def kasiski_test(s):
    '''
        >>> s = B(b'ABCDBCDABCDBC')
        >>> kasiski_test(s)
    '''
    res = []
    l = as_3ngram_repeated_positions(s)
    while l:
        delta_stats = Counter()
        for _, positions in l:
            d = deltas_from_positions(positions)
            delta_stats.update(Counter(d))

        res.append(delta_stats)
        l = merge_overlaping(l)

    return res
