import heapq
import collections
import collections.abc
import itertools
import functools
from operator import itemgetter, mul as mul_func
'''
>>> # Convenient definitions
>>> from cryptonita import B           # byexample: +timeout=10
>>> from cryptonita.fuzzy_set import *

'''


class FuzzySet(dict, collections.abc.Set):
    # TODO talk about this!
    def __init__(self, iterable=(), pr=None, min_membership=0.0):
        ''' Create a FuzzySet from an iterable.

            If you have a dictionary where the values represent the
            probability or membership of the key you can use it directly

            >>> FuzzySet({'a': 1, 'b': 0.8, 'c': 0.4})
            {'a' -> 1.0000, 'b' -> 0.8000, 'c' -> 0.4000}

            You can cut the set setting a minimum for the membership:

            >>> FuzzySet({'a': 1, 'b': 0.8, 'c': 0.4}, min_membership=0.5)
            {'a' -> 1.0000, 'b' -> 0.8000}

            Note that the min_membership effect will persist.

            If you don't have a dict, you can use two iterables

            >>> FuzzySet(['a', 'b', 'c'], [1, 0.8, 0.4], min_membership=0.5)
            {'a' -> 1.0000, 'b' -> 0.8000}

            or you can use this python trick to unpack a list of tuples and
            get the same effect:

            >>> FuzzySet(*zip(*[('a', 1), ('b', 0.8), ('c', 0.4)]), min_membership=0.5)
            {'a' -> 1.0000, 'b' -> 0.8000}

            or, as a shortcut, set pr to 'tuple'.

            >>> FuzzySet([('a', 1), ('b', 0.8), ('c', 0.4)], pr='tuple', min_membership=0.5)
            {'a' -> 1.0000, 'b' -> 0.8000}

            You can build a fuzzy set from a set of keys. In this case you
            need to set a default probability or membership for all the keys:

            >>> FuzzySet(['a', 'b', 'c'], pr=0.8)
            {'c' -> 0.8000, 'b' -> 0.8000, 'a' -> 0.8000}

            If the default is omitted, 1.0 is used:

            >>> FuzzySet(['a', 'b', 'c'])
            {'c' -> 1.0000, 'b' -> 1.0000, 'a' -> 1.0000}

        '''

        self.min_membership = min_membership
        self._check_probability(None, min_membership, True)

        if not isinstance(iterable, dict):
            if pr is None:
                iterable = ((k, 1.0) for k in iterable)

            elif isinstance(pr, (float, int)):
                pr = float(pr)
                iterable = ((k, pr) for k in iterable)

            elif pr == 'tuple':
                iterable = iterable

            else:
                iterable = zip(iterable, pr)

            iterable = ((k, pr) for (k, pr) in iterable if pr > min_membership)

        else:
            iterable = (
                (k, pr) for (k, pr) in iterable.items() if pr > min_membership
            )

        dict.__init__(self, iterable)
        [self._check_probability(k, pr) for k, pr in self.items()]

    def __repr__(self):
        items = sorted(self.items(), key=itemgetter(1, 0), reverse=True)
        return '{' + ', '.join(
            '%s -> %0.4f' % (repr(k), p) for k, p in items
        ) + '}'

    def _check_probability(self, elem, prob, about_min_membership=False):
        if not (0 <= prob <= 1):
            if about_min_membership:
                raise ValueError(
                    "The minimum membership is %0.4f but it must be a value between 0 and 1."
                    % (prob)
                )
            else:
                raise ValueError(
                    "The membership of %s is %0.4f but it must be a value between 0 and 1."
                    % (repr(elem), prob)
                )

    def copy(self):
        return FuzzySet(self, min_membership=self.min_membership)

    def most_likely(self, n=None):
        '''
            >>> g = FuzzySet(['a', 'b', 'c'], [0.9, 0.8, 0.7])

            >>> g
            {'a' -> 0.9000, 'b' -> 0.8000, 'c' -> 0.7000}

            >>> g.most_likely()
            'a'

            >>> g.most_likely(2)
            ('a', 'b')

            '''
        nlargest = heapq.nlargest(
            1 if n == None else n, self.items(), key=itemgetter(1)
        )
        if n == None:
            return nlargest[0][0]
        else:
            return tuple(zip(*nlargest))[0]

    def __setitem__(self, elem, prob):
        r'''Add an element to the set and assign it a value of <prob>.

            >>> g = FuzzySet()

            >>> g['a'] = 0.51
            >>> g['b'] = 1
            >>> g['c'] = 0.7

            >>> g
            {'b' -> 1.0000, 'c' -> 0.7000, 'a' -> 0.5100}

            We support updates

            >>> g['a'] = 0.3
            >>> g
            {'b' -> 1.0000, 'c' -> 0.7000, 'a' -> 0.3000}

            The value of <prob> is the probability of the element to be in the
            set. Therefore it must be a value between 0 and 1.

            Zero values are discarded:
            >>> g['d'] = 0
            >>> g
            {'b' -> 1.0000, 'c' -> 0.7000, 'a' -> 0.3000}

            Greater than 1 (or negative) raise an exception:
            >>> g['e'] = 42
            Traceback (most recent call last):
            <...>
            ValueError: The membership of 'e' is 42.0000 but it must be a value between 0 and 1.

            The FuzzySet can be configured to drop and not save any key lower
            than a given threshold:

            >>> g.min_membership = 0.4
            >>> g
            {'b' -> 1.0000, 'c' -> 0.7000}

            >>> g['d'] = 0.1
            >>> g
            {'b' -> 1.0000, 'c' -> 0.7000}

            >>> g['c'] = 0.1
            >>> g
            {'b' -> 1.0000}

        '''

        self._check_probability(elem, prob)
        if prob < self.min_membership or prob == 0:
            if elem in self:
                del self[elem]

            # drop and don't save
            return

        dict.__setitem__(self, elem, prob)

    @property
    def min_membership(self):
        return self._min_membership

    @min_membership.setter
    def min_membership(self, pr):
        self._check_probability(None, pr, True)
        self._min_membership = pr

        self.cut_off(self._min_membership)

    def __getitem__(self, elem):
        return dict.get(self, elem, 0)

    def cut_off(self, n):
        r'''If <n> is an integer, drop all the elements except
            the <n> most likely ones.

            >>> g = FuzzySet(['a', 'b', 'c'], [0.9, 0.8, 0.7])

            >>> g
            {'a' -> 0.9000, 'b' -> 0.8000, 'c' -> 0.7000}

            >>> g.cut_off(2)
            >>> g
            {'a' -> 0.9000, 'b' -> 0.8000}

            If <n> is between 0 and 1, drop all the elements which
            probability is lower than <n>.

            >>> g.cut_off(0.85)
            >>> g
            {'a' -> 0.9000}

        '''

        if isinstance(n, int):
            nlargest = heapq.nlargest(n, self.items(), key=itemgetter(1))
            self.clear()
            dict.update(self, nlargest)

        else:
            for k in list(self.keys()):
                if self[k] < n:
                    del self[k]

    def scale(self, n):
        r'''Readjust the probability/membership of all the elements
            multiplying them by <n>.

            >>> g = FuzzySet(['a', 'b', 'c', 'd'], [0.4, 0.4, 0.8, 0.4])

            >>> g.scale(0.5)
            >>> g
            {'c' -> 0.4000, 'd' -> 0.2000, 'b' -> 0.2000, 'a' -> 0.2000}
        '''
        for k in self:
            self[k] *= n

    def normalize(self):
        r'''Makes the sum of all the elements to be 1.

            >>> g = FuzzySet(['a', 'b', 'c', 'd'], [0.4, 0.4, 0.8, 0.4])
            >>> g.normalize()
            >>> g
            {'c' -> 0.4000, 'd' -> 0.2000, 'b' -> 0.2000, 'a' -> 0.2000}
        '''
        s = sum(pr for pr in self.values())
        if s > 0:
            self.scale(1.0 / s)

    def update(self, other):
        r'''Perform the union of this set and the <other> and update self
            with the union.

            >>> g = FuzzySet(['a', 'b'], 0.5)

            >>> g.update(FuzzySet(['a', 'c'], [1, 0.2]))
            >>> g
            {'a' -> 1.0000, 'b' -> 0.5000, 'c' -> 0.2000}

        '''

        tmp = self.union(other)
        self.clear()
        dict.update(self, tmp)

    def intersection(self, other):
        r'''Return a fuzzy sets with elements that are present in both
            sets with the minimum of both membership.

            >>> a = FuzzySet(['a', 'b'], (0.7, 0.4))
            >>> b = FuzzySet(['a', 'b', 'c'], (1.0, 0.2, 0.1))

            >>> a.intersection(b)
            {'a' -> 0.7000, 'b' -> 0.2000}

            >>> a & b
            {'a' -> 0.7000, 'b' -> 0.2000}

        '''

        tmp = FuzzySet()
        min_set = other if len(other) < len(self) else self
        max_set = other if min_set is self else self

        for k, pr in min_set.items():
            tmp[k] = min(max_set[k], pr)

        return tmp

    def union(self, other):
        r'''Return a fuzzy sets with elements of both
            sets with the maximum of both membership.

            >>> a = FuzzySet(['a', 'b'], (0.7, 0.4))
            >>> b = FuzzySet(['a', 'b', 'c'], (1.0, 0.2, 0.1))

            >>> a.union(b)
            {'a' -> 1.0000, 'b' -> 0.4000, 'c' -> 0.1000}

            >>> a | b
            {'a' -> 1.0000, 'b' -> 0.4000, 'c' -> 0.1000}

        '''
        max_set = other if len(other) > len(self) else self
        min_set = other if max_set is self else self

        tmp = FuzzySet(max_set)
        for k, pr in min_set.items():
            tmp[k] = max(tmp[k], pr)

        return tmp

    def issubset(self, other):
        r'''Return True if self is a subset of the fuzzy set <other>.
            Be a subset means that all the elements in self
            are present in <other> and with a lesser membership
            value.

            >>> a = FuzzySet(['a', 'b'], (0.7, 0.4))
            >>> b = FuzzySet(['a', 'b', 'c'], (1.0, 0.2, 0.1))

            >>> a.issubset(b)
            False

            >>> a['b'] = 0.2
            >>> a.issubset(b)
            True

            >>> b.issuperset(a)
            True

            In other words, A is a subset of B if A union B yields B

            >>> a.union(b) == b
            True

        '''
        for k, pr in self.items():
            if pr > other[k]:
                return False

        return True

    def issuperset(self, other):
        return other.issubset(self)

    def __and__(self, other):
        return self.intersection(other)

    def __or__(self, other):
        return self.union(other)

    def __iand__(self, other):
        tmp = self.intersection(other)
        self.clear()
        dict.update(self, tmp)
        return self

    def __ior__(self, other):
        self.update(other)
        return self

    def sorted_items(self, most_likely_first=True):
        reverse = most_likely_first
        return sorted(self.items(), key=itemgetter(1, 0), reverse=reverse)

    def sorted_keys(self, most_likely_first=True):
        return (k for k, _ in self.sorted_items(most_likely_first))

    def sorted_values(self, most_likely_first=True):
        return (v for _, v in self.sorted_items(most_likely_first))

    @staticmethod
    def join(iterable, cut_off, j):
        return join_fuzzy_sets(iterable, cut_off, j)


def join_fuzzy_sets(iterable, cut_off, j):
    r'''
        Join the given fuzzy sets and return a single one.

        Combine all the elements of all the sets, in order, and
        build all the possible strings from that combination,
        joining the pieces with <j>.

        Each string it has a probability equals to the multiplication
        of the individual probabilities of each piece.

        For example:

        >>> A = FuzzySet(dict(y=0.9, a=0.6))
        >>> B = FuzzySet(dict(j=0.7, e=0.6))
        >>> C = FuzzySet(dict(s=0.4))

        >>> join_fuzzy_sets([A, B, C], cut_off=0.0, j='')
        {'yjs' -> 0.2520, 'yes' -> 0.2160, 'ajs' -> 0.1680, 'aes' -> 0.1440}

        Because the join produces a string for each possible combination, the
        size of the resulting set is equal to the product of the sizes of the
        input sets.

        To avoid blowing up the memory, the <cut_off> parameter can be used
        to filter away any resulting string that has a lesser than <cut_off>
        value.

        >>> join_fuzzy_sets([A, B, C], cut_off=0.2, j='')
        {'yjs' -> 0.2520, 'yes' -> 0.2160}

        If <cut_off> is greater or equal than 1, it will be interpreted as
        the number of the most probable strings instead of a minimum probability.

        >>> join_fuzzy_sets([A, B, C], cut_off=3, j='')
        {'yjs' -> 0.2520, 'yes' -> 0.2160, 'ajs' -> 0.1680}

        >>> join_fuzzy_sets([A, B, C], cut_off=1, j='')
        {'yjs' -> 0.2520}

    '''

    assert 0 <= cut_off

    if cut_off >= 1:
        counters = [len(fs) for fs in iterable]

        vals = [
            [(pr, idx) for pr in fs.values()]
            for idx, fs in enumerate(iterable)
        ]
        vals = sorted(sum(vals, []))

        for _, idx in vals:
            if counters[idx] == 1:
                continue  # skip it, at least 1 key of each fuzzy set must survive

            counters[idx] -= 1

            if functools.reduce(mul_func, counters) <= cut_off:
                counters[idx] += 1
                break

        sets = []
        for fs, counter in zip(iterable, counters):
            fs = fs.copy()
            fs.cut_off(counter)  # TODO optimize this
            sets.append(fs)

        upper_set = join_fuzzy_sets(sets, cut_off=0.0, j=j)
        upper_set.cut_off(cut_off)
        return upper_set

    all_possibilities = itertools.product(*(fs.items() for fs in iterable))

    def xxx(elems):
        byte_seq, probs = zip(*elems)

        seq_prob = 1
        for p in probs:
            seq_prob *= p

        return byte_seq, seq_prob

    # calculate the probability for each sequence
    tmp = (xxx(elems) for elems in all_possibilities)

    # filter out the less likely and join the remain byte sequences
    tmp = ((j.join(byte_seq), pr) for byte_seq, pr in tmp if pr >= cut_off)

    # build up the fuzzy set
    return FuzzySet(dict(tmp))


def len_join_fuzzy_sets(iterable):
    x = 1
    for k in iterable:
        x *= len(k)
    return x
