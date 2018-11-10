'''
>>> # Convenient definitions
>>> from cryptonita import B
'''

import math

class InfiniteStream(bytes):
    def __getitem__(self, idx):
        if isinstance(idx, slice):
            raise TypeError("We don't support slicing (yet).")

        return super().__getitem__(idx % super().__len__())

    def __iter__(self):
        r'''
            Return an iterator of this infinite stream of bytes.
            Basically we take a finite sequence and we repeat it
            infinite times:

                >>> s = B(b'\x01\x02').inf()

                >>> i = iter(s)
                >>> next(i), next(i), next(i), next(i)
                (1, 2, 1, 2)

            '''
        it = super().__iter__()
        while True:
            try:
                yield next(it)
            except StopIteration:
                it = super().__iter__()

    def __repr__(self):
        '''
                >>> B(b'ABCD').inf()
                .. 'ABCD' ..
        '''
        return '.. ' + super().__repr__()[1:] + ' ..'

    def __len__(self):
        raise TypeError("The length of an endless stream is undefined. You may think it is infinity.")

from cryptonita.mixins import SequenceStatsMixin
class NgramsView(SequenceStatsMixin):
    ''' N-grams view of a byte string.

        A n-gram is a sequence of n bytes that overlaps
        each other.

            >>> s = B('ABCDE')
            >>> ngrams = s.ngrams(3)

            >>> list(ngrams)
            ['ABC', 'BCD', 'CDE']

        Shorter and larger sequences are ok

            >>> list(B('ABC').ngrams(3))
            ['ABC']

            >>> list(B('ABCDEFGHI').ngrams(3))
            ['ABC', 'BCD', 'CDE', 'DEF', 'EFG', 'FGH', 'GHI']

        But too short aren't

            >>> list(B('AB').ngrams(3))
            Traceback <...>
            <...>
            ValueError: The byte string has only 2 bytes. It is not possible to create even a single ngram of length 3.

        A n-gram sequence supports:

            >>> len(ngrams)
            3

            >>> ngrams[1]
            'BCD'

        But slicing is not supported (yet)

            >>> ngrams[1:2]
            Traceback <...>
            <...>
            TypeError: We don't support slicing (yet).

        This also support some basic statistics:

            >>> ngrams = B('ABABABC').ngrams(2)
            >>> ngrams.freq()           # TODO not yet!! # byexample: +skip
            Counter({b'AB': 3, b'BA': 2, b'BC': 1})

            >>> ngrams.most_common(n=2)        # TODO not yet!! # byexample: +skip
            ('AB', 'BA')

            >>> ngrams.entropy()        # TODO not yet!! # byexample: +skip
            1.0114042647073<...>

    '''
    __slots__ = ('_raw', '_n')

    def __init__(self, raw, n):
        if len(raw) < n:
            raise ValueError("The byte string has only %i bytes. It is not possible to create even a single ngram of length %i." % (len(raw), n))

        self._raw = raw
        self._n = n

    def __iter__(self):
        s = self._raw
        n = self._n
        return (s[i:i+n] for i in range(len(self)))

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            raise TypeError("We don't support slicing (yet).")

        return self._raw[idx:idx+self._n]

    def __len__(self):
        return len(self._raw) - self._n + 1

class NblocksView(SequenceStatsMixin):
    ''' N-blocks view of a byte string.

        A n-block is a sequence of n bytes that do not overlap
        each other.

            >>> s = B('ABCDEF')
            >>> nblocks = s.nblocks(3)

            >>> list(nblocks)
            ['ABC', 'DEF']

        When the length of a sequence is not a multiple of n, the last
        block will have less than n bytes

            >>> list(B('ABC').nblocks(3))
            ['ABC']

            >>> list(B('ABCDEFGHIJK').nblocks(3))
            ['ABC', 'DEF', 'GHI', 'JK']

            >>> len(B('ABCDEFGHIJK').nblocks(3))
            4


        A n-blok sequence supports:

            >>> len(nblocks)
            2

            >>> nblocks[1]
            'DEF'

        But slicing is not supported (yet)

            >>> nblocks[1:2]
            Traceback <...>
            <...>
            TypeError: We don't support slicing (yet).


        This also support some basic statistics:

            >>> nblocks = B('ABABCABAABBA').nblocks(2)
            >>> nblocks.freq()        # TODO not yet!! # byexample: +skip
            Counter({b'AB': 3, b'BA': 2, b'CA': 1})

            >>> nblocks.most_common(n=2)        # TODO not yet!! # byexample: +skip
            ('AB', 'BA')

            >>> nblocks.entropy()        # TODO not yet!! # byexample: +skip
            1.0114042647073<...>

    '''
    def __init__(self, raw, n):
        self._raw = raw
        self._n = n

    def __iter__(self):
        s = self._raw
        n = self._n
        return (s[i*n:(i+1)*n] for i in range(len(self)))

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            raise TypeError("We don't support slicing (yet).")

        n = self._n
        return self._raw[idx*n:(idx+1)*n]

    def __len__(self):
        return math.ceil(len(self._raw) / self._n)

