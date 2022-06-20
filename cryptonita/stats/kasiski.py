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


def as_ngram_repeated_positions(s, n, allow_overlapping=True):
    ''' Given a string of bytes returns a sorted list of (position, id) tuples.

        >>> s = B(b'ABCDBCDABCDBC')
        >>> pos_sorted = as_ngram_repeated_positions(s, n=3)

        The sorted list is a list of tuples which map the position
        of each non-unique ngram and the ngram's id, all sorted by
        position.

        In this case, the ngram of length 3:

        >>> pos_sorted
        [(0, 1), (1, 2), (2, 3), (3, 4), (4, 2), (7, 1), (8, 2), (9, 3), (10, 4)]

        In other words at position 0 there is a non-unique ngram 1, at position
        1 there is another non-unique ngram 2, .... at position 4 there is
        the same non-unique ngram 2 found at the position 1, ...

        Storing the ngrams by value (substrings) is expensive. Instead we
        use an unique identifier for each ngram (and integer).

        If two positions have the same id, it means that both point to the
        same ngram:

        >>> [p for p, id in pos_sorted if id == 4]
        [3, 10]

        In this case if we access to those two positions we will see the same
        substring:

        >>> s[3:3+3], s[10:10+3]
        ('DBC', 'DBC')

        By definition of a ngram, we will return overlapping positions:

        >>> s = B(b'ABABABAB')
        >>> as_ngram_repeated_positions(s, n=4)
        [(0, 1), (1, 2), (2, 1), (3, 2), (4, 1)]

        Note how the ngram number 1 (ABAB) that was found in the position 0
        (pair (0,1)) was also found in the position 2 (pair (2,1)).

        Currently NOT supported but it should be possible to filter the ngrams
        that overlaps with themselves.
        This may also remove the whole ngrams if the resulting becomes unique.

        In the following example we removed the overlapping ngrams of ABAB
        and BABA. In the latter the ngram BABA disappeared:

        >>> as_ngram_repeated_positions(s, n=4, allow_overlapping=False)    # byexample: +skip
        [(0, 1), (4, 1)]

        Again, NOT supported yet.
        '''

    # Map each ngram to its own identifier and add to the pos_sorted list
    # the positions and ids in order.
    # During the scanning, count how many ngrams we see of each ngram type.
    #
    # Assuming a O(1) hash implementation, this is Time/Space O(n)
    id_of_ngram = {0: 0}
    pos_sorted = []
    ngram_cnt_by_id = defaultdict(
        int, [(0, 0)]
    )  # id==0 is special with a count of 0 always
    for pos, ngram in enumerate(s.ngrams(n)):
        id = id_of_ngram.setdefault(ngram, len(id_of_ngram))

        pos_sorted.append((pos, id))
        ngram_cnt_by_id[
            id] += 1  # because the ids goes from 1 to N we could use an array

    # Filter any unique ngram (count of 0)
    # This is Time/Space O(n)
    pos_sorted = [(p, id) for p, id in pos_sorted if ngram_cnt_by_id[id] > 1]

    return pos_sorted


def merge_overlaping(pos_sorted):
    '''
        Given a list of positions and ngram identities sorted
        by the position (see as_ngram_repeated_positions)
        where the ngrams are of length N, create another
        pos_sorted list for ngrams of length N+1
        discarding any unique ngram (we are interested in the repeated ones)

        The idea is that two ngrams G1 and G2 of N bytes at positions
        P1 and P2 can be merged if they satisfy P1 + 1 == P2 (that does
        not imply that the ngram built is repeated, but it is a precondition)

        >>> #           10--\ 11  /--12
        >>> # positions      \ | /
        >>> #       0123456789|||
        >>> s = B(b'ABCDBCDABCDBC')
        >>> l3_positions = as_ngram_repeated_positions(s, n=3)
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
        >>> l3_positions = as_ngram_repeated_positions(s, n=3)
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
    id_of_ngram = {0: 0}
    ngram_cnt_by_id = defaultdict(int, [(0, 0)])
    for ix, (cur, nex) in enumerate(zip(pos_sorted[:-1], pos_sorted[1:])):
        pcur, id = cur
        pnex, id2 = nex

        if pcur + 1 != pnex:
            pos_sorted[ix] = (0, 0)  # delete later (index 0 is special)
        else:
            # instead of building the ngram from G1 and G2 we use
            # G1's and G2's identifiers as a temporally ngram representation
            # to map the new larger ngram to an new identifier
            # Note how (id, id2) means that the ngram was built from G1 and G2
            # *in that order* (G2 and G1 gives another ngram of course so
            # the (id, id2) tuple order is important)
            id = id_of_ngram.setdefault((id, id2), len(id_of_ngram))

            pos_sorted[ix] = (pcur, id)  # new ngram
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


def deltas_from_positions(positions):
    '''
        Return the difference between consecutive positions.
        If the input is sorted, the deltas returned will be always
        positive.

        This computes the difference between 0 and 7:

        >>> list(deltas_from_positions([0, 7]))
        [7]

        This computes the difference between 1 and 4,
        and 4 and 8:

        >>> list(deltas_from_positions([1, 4, 8]))
        [3, 4]

        This is another example:

        >>> list(deltas_from_positions([1, 4, 7, 11]))
        [3, 3, 4]

    '''
    # Time O(n)
    return (y - x for x, y in zip(positions[:-1], positions[1:]))


def frequency_of_deltas(s, start=3, end=None):
    '''
        Return a list of frequencies of gaps between repeated n-grams.

        >>> s = B(b'ABCDBCDABCDBC')
        >>> frequency_of_deltas(s)
        [Counter({7: 3, 3: 1, 4: 1}), Counter({7: 3}), Counter({7: 2}), Counter({7: 1})]

        The first frequencies corresponds to the 3-grams: a gap between
        two repeated 3-grams of length 7 was found 4 times; of length 3
        was found once and of length of 4 was found once.

        The next element in the returned list are the frequencies
        of the gaps between 4-grams repeated. In this case we have a single
        gap of length 7 repeated 3 times.

        The next element is for gaps between 5-grams, and so on.

        A subrange of frequencies can be obtained. For example we could be
        interested in only the frequencies of the 4-ngrams and 5-ngrams only.

        It is faster to do then the following (<end> is not inclusive):

        >>> frequency_of_deltas(s, start=4, end=6)
        [Counter({7: 3}), Counter({7: 2})]
    '''
    res = []
    n = start
    pos_sorted = as_ngram_repeated_positions(s, n=n)
    while pos_sorted:
        # we group the positions by id: each group of positions
        # will have the same identifier and therefore will belong
        # to the same ngram.
        #
        # The grouping preserves the order of the positions: positions
        # of the same ngram will stay sorted.
        #
        # This makes the compute of deltas easier (see
        # deltas_from_positions)
        #
        # O(n)
        pos_grouped = defaultdict(list)
        for pos, id in pos_sorted:
            pos_grouped[id].append(pos)

        # for each group (ngram) compute the differences between
        # its positions or "gaps"
        # This is O(n)
        delta_stats = Counter()
        for positions in pos_grouped.values():
            d = deltas_from_positions(positions)
            delta_stats.update(Counter(d))

        res.append(delta_stats)

        n += 1
        if end is not None and n >= end:
            break
        pos_sorted = merge_overlaping(pos_sorted)

    return res


def sort_deltas_by_probability(deltas_freqs):
    ''' Given a deltas frequencies of deltas of ngrams of different lengths,
        sort them by probability.

        The input for the function is a list of frequencies where the first
        element are the frequencies of the ngrams of length <n>, the second
        element are of ngrams of length <n+1>, then <n+2> and so on.

        >>> deltas_freqs = [Counter({7: 3, 9: 1}), Counter({9: 1})]

        A delta repeated several times produced by larger ngrams are much less
        likely to be product of random or luck. Instead, they should be
        the product of a coincidence between the plaintext and the key leaked
        in the ciphertext of a repeated key (Vigenere cihper).

        The function returns a list of tuples with the deltas and
        their "probability" sorted them from the less likely to the
        more likely to be random.

        For performance reasons an exponent is used instead of probability:
        larger exponent, lower probability.

        >>> list(sort_deltas_by_probability(deltas_freqs))
        [(7, 3), (9, 2), (9, 1)]

        Note: in the above example Counter({9: 1}) means that a ngram of
        length n+1 is repeated once with a distance of 9. Intuitively it should
        be less likely to be random however it is *much less* likely the
        distance of 7 that it was found 3 times even if the length of
        the ngrams is n and not n+1.

        That's why 7 is the correct answer and not 9.
        '''

    res = (
        (delta, freq * n) for n, freqs in enumerate(deltas_freqs, 1)
        for delta, freq in freqs.items()
    )
    return sorted(res, key=itemgetter(1), reverse=True)
