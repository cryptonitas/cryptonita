'''
>>> from cryptonita.conv import B           # byexample: +timeout=10
>>> from cryptonita.stats.kasiski import *
'''

from cryptonita.conv import B
from bisect import bisect_left

from operator import itemgetter
from collections import defaultdict
import itertools

from collections import Counter

# References:
# Automating the Cracking of Simple Ciphers, Matthew C. Berntsen

def as_3ngram_repeated_positions(s):
    ''' Given a string of bytes returns a sorted list of (position, id) tuples.

        >>> s = B(b'ABCDBCDABCDBC')
        >>> pos_sorted = as_3ngram_repeated_positions(s)

        The sorted list is a list of tuples which map the position
        of each non-unique ngram and the ngram's id, all sorted by
        position:

        >>> pos_sorted
        [(0, 1), (1, 2), (2, 3), (3, 4), (4, 2), (7, 1), (8, 2), (9, 3), (10, 4)]

        Storing the ngrams by value (substrings) is expensive. Instead we
        use an unique identifier for each ngram (and integer).

        If two positions have the same id, it means that both point to the
        same ngram:

        >>> [p for p, id in pos_sorted if id == 4]
        [3, 10]

        >>> s[3:3+3], s[10:10+3]
        ('DBC', 'DBC')

        '''

    # Map each ngram to its own identifier and add to the pos_sorted list
    # the positions and ids in order.
    # During the scanning, count how many ngrams we see of each ngram type.
    #
    # Assuming a O(1) hash implementation, this is Time/Space O(n)
    id_of_ngram = {0:0}
    pos_sorted = []
    ngram_cnt_by_id = defaultdict(int, [(0,0)]) # id==0 is special with a count of 0 always
    for pos, ngram in enumerate(s.ngrams(3)):
        id = id_of_ngram.setdefault(ngram, len(id_of_ngram))

        pos_sorted.append((pos, id))
        ngram_cnt_by_id[id] += 1        # because the ids goes from 1 to N we could use an array

    # Filter any unique ngram (count of 0)
    # This is Time/Space O(n)
    pos_sorted = [(p, id) for p, id in pos_sorted if ngram_cnt_by_id[id] > 1]

    return pos_sorted

def merge_overlaping(pos_sorted):
    '''
        Given a list of positions and ngram identities sorted
        by the position (see as_3ngram_repeated_positions)
        where the ngrams are of length N, create another
        pos_sorted list for ngrams of length N+1
        discarding any unique ngram (we are interested in the repeated ones)

        The idea is that two ngrams G1 and G2 of N bytes at positions
        P1 and P2 can be merged if they satisfy P1 + 1 == P2 (that does
        not imply that the ngram built is repeated, but it is a precondition)

        >>> #       0123456789ABC
        >>> s = B(b'ABCDBCDABCDBC')
        >>> l3_positions = as_3ngram_repeated_positions(s)
        >>> [p for p, _ in l3_positions]
        [0, 1, 2, 3, 4, 7, 8, 9, 10]

        The result can be interpreted as at the positions 0 to 10 except 5 and 6
        there are a 3-ngram that are repeated.

        >>> l4_positions = merge_overlaping(l3_positions)
        >>> [p for p, _ in l4_positions]
        [0, 1, 2, 7, 8, 9]

        Now, the positions were are 4-ngrams repeated is smaller: 0 to 2
        and 7 to 9.

        >>> l5_positions = merge_overlaping(l4_positions)
        >>> [p for p, _ in l5_positions]
        [0, 1, 7, 8]

        If you want to recover the ngrams you just need
        to use the positions to get the substrings

        >>> [s[p:p+5] for p, _ in l5_positions]
        ['ABCDB', 'BCDBC', 'ABCDB', 'BCDBC']

        If we print the ngrams' identities we will see two
        numbers: one for ABCDB and the other for BCDBC:

        >>> [id for _, id in l5_positions]
        [1, 2, 1, 2]

        Continuing with the merging:

        >>> l6_positions = merge_overlaping(l5_positions)
        >>> [p for p, _ in l6_positions]
        [0, 7]

        >>> l7_positions = merge_overlaping(l6_positions)
        >>> l7_positions
        []

        >>> s = B(b'ABCDxABCExBCDyBCE')
        >>> l3_positions = as_3ngram_repeated_positions(s)
        >>> l4_positions = merge_overlaping(l3_positions)
        >>> [p for p, _ in l4_positions]
        []
        '''

    # For each position P1 see if there is a P2 such as P1 + 1 == P2.
    # That would mean that in a P1 we have a ngram G1 of length N and
    # in P2 we have another ngram G2 of length N and both share N-1 bytes.
    # In particular, G1[1:] == G2[:-1].
    # This means that in P1 we have a ngram of length N+1 which value
    # is G1 + G2[-1]  (or G1[0] + G2)
    # Because G1 and G2 are ngrams that repeat, the new ngram G1 + G2[-1]
    # *may* be repeated: the algorithm produces false positives
    #
    # If for a position P1 we don't find such P2, we mark it to be deleted
    # because we didn't find any ngram of N+1 in P1. We can be *sure*
    # that a N+1 ngram will not exist: the algorithm does not produce
    # false negatives.
    #
    # This is a Time/Space O(n)
    id_of_ngram = {0:0}
    ngram_cnt_by_id = defaultdict(int, [(0,0)])
    K = len(pos_sorted) // 2
    for i in range(len(pos_sorted)-1):
        cur, id  = pos_sorted[i]
        nex, id2 = pos_sorted[i+1]

        if cur + 1 != nex:
            pos_sorted[i] = (0, 0) # delete later (index 0 is special)
        else:
            # instead of building the ngram from G1 and G2 we use
            # G1's and G2's identifiers as a temporally ngram representation
            # to map the new larger ngram to an new identifier
            # Note how (id, id2) means that the ngram was built from G1 and G2
            # *in that order* (G2 and G1 gives another ngram of course so
            # the (id, id2) tuple order is important)
            id = id_of_ngram.setdefault((id, id2), len(id_of_ngram))

            pos_sorted[i] = (cur, id)   # new ngram
            ngram_cnt_by_id[id] += 1

    # the last position P1 always is deleted because there is
    # not P2 such P1 + 1 == P2 *and* P1 < P2 (basically because there
    # are no more positions after P1)
    pos_sorted[-1] = (0, 0)

    # filter any position marked to be deleted (their index is 0)
    # or if it is the position to a ngram that appears once.
    # Time/Space O(n)
    pos_sorted = [(p, id) for p, id in pos_sorted if ngram_cnt_by_id[id] > 1]

    return pos_sorted

def deltas_from_positions(positions, is_sorted=True):
    '''
        Return the difference between the positions in any combination.
        If the input is sorted, the deltas returned will be always
        positive.

        >>> deltas_from_positions([0, 7])
        [7]

        >>> deltas_from_positions([1, 4, 8])
        [3, 7, 4]

        >>> deltas_from_positions([1, 4, 7, 11])
        [3, 6, 10, 3, 7, 4]

        If the input is not sorted, the delta will contain negative
        values. Pass is_sorted=False to notify about this and force
        the values to be positive.

        >>> deltas_from_positions([4, 7, 1, 11], is_sorted=False)
        [3, 3, 7, 6, 4, 10]

    '''
    # Python itertools' combinations function returns pairs maintaining
    # the same order that the input has. So if the input is sorted
    # (x1, x2, x3, ...) such x1 <= x2 <= x3 <= ..., then the output
    # will be ((x1, x2), (x1, x3), ... (x2, x3), (x2, x4) ...) so
    # the first value of each tuple always equal or less than the second
    # item so the difference is always positive.
    #
    # Time O(n^2)
    if is_sorted:
        return [y-x for x, y in itertools.combinations(positions, 2)]
    else:
        return [abs(y-x) for x, y in itertools.combinations(positions, 2)]

def kasiski_test(s):
    '''
        Return a list of frequencies of gaps between n-grams.

        >>> s = B(b'ABCDBCDABCDBC')
        >>> kasiski_test(s)
        [Counter({7: 4, 3: 1, 4: 1}), Counter({7: 3}), Counter({7: 2}), Counter({7: 1})]

        The first frequencies corresponds to the 3-grams: a gap between
        two repeated 3-grams of length 7 was found 4 times; of length 3
        was found once and of length of 4 was found once.

        The next element in the returned list are the frequencies
        of the gaps between 4-grams repeated. In this case we have a single
        gap of length 7 repeated 3 times.

        The next element is for gaps between 5-grams, and so on.
    '''
    res = []
    pos_sorted = as_3ngram_repeated_positions(s)
    while pos_sorted:
        # we sort the positions+ids by id and then we
        # group the positions by id: each group of positions
        # will have the same identifier and therefore will belong
        # to the same ngram.
        #
        # Because Python's sorted() algorithm is stable and
        # the original pos_sorted list is already sorted by position,
        # the sorted(...) leaves the list sorted by id
        # *and* secondly sorted by position (within each group)
        #
        # This serves for two things:
        #   - groupby requires the input to be sorted by the key to group by
        #   - deltas_from_positions returns positive deltas if the input
        #     (the positions) are sorted
        #
        # O(n log n)
        pos_grouped = sorted(pos_sorted, key=itemgetter(1))
        pos_grouped = itertools.groupby(pos_grouped, key=itemgetter(1))

        # for each group (ngram) compute the differences between
        # its positions or "gaps"
        # This is O(n^2)
        delta_stats = Counter()
        for _, tmp in pos_grouped:
            positions = (p for p, _ in tmp)
            d = deltas_from_positions(positions)
            delta_stats.update(Counter(d))

        res.append(delta_stats)
        pos_sorted = merge_overlaping(pos_sorted)

    return res
