import collections
import collections.abc
'''
>>> from cryptonita.helpers import bisect_left_rev, bisect_right_rev
'''


def are_same_length_or_fail(a, b):
    if len(a) != len(b):
        raise ValueError("Mismatch lengths. Left string has %i bytes but right string has %i." % \
                            (len(a), len(b)))


def are_bytes_or_fail(val, name):
    if not isinstance(val, collections.abc.ByteString):
        raise TypeError("The parameter '%s' should be a bytes-like instance but it is %s." % \
                            (name, type(val)))


def indices_from_slice_or_index(idx, l, step_must_be_one):
    if isinstance(idx, slice):
        start, stop, step = idx.indices(l)
        if step != 1 and step_must_be_one:
            raise IndexError(
                "A slice with a step/stride different of 1 is not supported"
            )

    elif isinstance(idx, int):
        # if idx is -1, the naive stop (idx+1) would be 0 which
        # is interpreted as "first block" and not "the last block"
        # which it is what the user wants
        tmp = slice(idx, idx + 1 if idx != -1 else l)
        start, stop, step = tmp.indices(l)
    else:
        raise IndexError("Invalid object as index; expected a number or a slice but %s was found" \
                % type(idx))

    # it is guaranteed that the start, stop and step are positives
    return start, stop, step


def _bisect_chk(a, lo, hi):
    if lo < 0:
        raise ValueError("Low bound must be greater or equal to zero")
    if hi is None:
        hi = len(a)
    if hi > len(a):
        raise ValueError(
            "High bound must be lesser or equal to the length of the array"
        )

    return lo, hi


def bisect_right_rev(a, x, lo=0, hi=None):
    ''' Return the index where to insert item x in list a, assuming a is sorted
        in decreasing order. (for increasing order see bisect.bisect_left)

        The return value i is such that all e in a[:i] have e >= x, and all e in
        a[i:] have e < x.  So if x already appears in the list, i points just
        beyond the rightmost x already there.

        >>> a = [5, 4, 3, 3, 2]
        >>> i = bisect_right_rev(a, 4)
        >>> a[:i], a[i:]
        ([5, 4], [3, 3, 2])

        >>> i = bisect_right_rev(a, 3)
        >>> a[:i], a[i:]
        ([5, 4, 3, 3], [2])

        Optional args lo (default 0) and hi (default len(a)) bound the
        slice of a to be searched.
        '''

    lo, hi = _bisect_chk(a, lo, hi)
    while lo < hi:
        mid = (lo + hi) // 2
        if x > a[mid]: hi = mid
        else: lo = mid + 1
    return lo


def bisect_left_rev(a, x, lo=0, hi=None):
    ''' Return the index where to insert item x in list a, assuming a is sorted
        in decreasing order. (for increasing order see bisect.bisect_left)

        The return value i is such that all e in a[:i] have e > x, and all e in
        a[i:] have e <= x.  So if x already appears in the list, i points just
        before the leftmost x already there.

        >>> a = [5, 4, 3, 3, 2]
        >>> i = bisect_left_rev(a, 4)
        >>> a[:i], a[i:]
        ([5], [4, 3, 3, 2])

        >>> i = bisect_left_rev(a, 3)
        >>> a[:i], a[i:]
        ([5, 4], [3, 3, 2])

        Optional args lo (default 0) and hi (default len(a)) bound the
        slice of a to be searched.
        '''

    lo, hi = _bisect_chk(a, lo, hi)
    while lo < hi:
        mid = (lo + hi) // 2
        if x >= a[mid]: hi = mid
        else: lo = mid + 1
    return lo
