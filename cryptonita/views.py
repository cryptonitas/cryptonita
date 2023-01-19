'''
>>> # Convenient definitions
>>> from cryptonita import B           # byexample: +timeout=10
'''

import math
import itertools
from cryptonita.helpers import indices_from_slice_or_index
from cryptonita.conv import as_bytes


class InfiniteStream:
    __slots__ = ('base', )

    def __init__(self, base):
        self.base = base

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            n = len(self.base)
            start, stop, step = idx.start, idx.stop, idx.step
            start = start or 0
            step = step or 1

            return as_bytes(self.base[i % n] for i in range(start, stop, step))

        return self.base[idx % len(self.base)]

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
        if len(self.base) <= 2048:
            return itertools.cycle(self.base)
        else:
            return self._iter_long_seq()

    def _iter_long_seq(self):
        it = iter(self.base)
        while True:
            try:
                yield next(it)
            except StopIteration:
                it = iter(self.base)

    def __repr__(self):
        '''
                >>> B(b'ABCD').inf()
                ..'ABCD'..
        '''
        return '..' + repr(self.base) + '..'

    def __len__(self):
        raise TypeError(
            "The length of an endless stream is undefined. You may think it is infinity."
        )


from cryptonita.mixins import SequenceStatsMixin


class NgramsView(SequenceStatsMixin):
    ''' N-grams view of a byte string.

        A n-gram is a sequence of n bytes that overlaps
        each other.

            >>> s = B('ABCDE')
            >>> ngrams = s.ngrams(3)

            >>> ngrams
            ['ABC', 'BCD', 'CDE']

        Shorter and larger sequences are ok

            >>> B('ABC').ngrams(3)
            ['ABC']

            >>> B('ABCDEFGHI').ngrams(3)
            ['ABC', 'BCD', 'CDE', 'DEF', 'EFG', 'FGH', 'GHI']

        But too short aren't

            >>> B('AB').ngrams(3)
            Traceback <...>
            <...>
            ValueError: The byte string has only 2 bytes. It is not possible to create even a single ngram of length 3.

        This also support some basic statistics:

            >>> ngrams = B('ABABABC').ngrams(2)
            >>> ngrams.freq()
            Counter({'AB': 3, 'BA': 2, 'BC': 1})

            >>> ngrams.most_common(n=2)
            ('AB', 'BA')

            >>> ngrams.entropy()
            1.0114042647073<...>

    '''
    __slots__ = ('base', 'n')

    def __init__(self, base, n):
        if n <= 0:
            raise ValueError("The size of a ngram cannot be zero or negative.")

        if len(base) < n:
            raise ValueError(
                "The byte string has only %i bytes. It is not possible to create even a single ngram of length %i."
                % (len(base), n)
            )

        self.base = base
        self.n = n

    def __iter__(self):
        n = self.n
        return (self.base[i:i + n] for i in range(len(self)))

    def __getitem__(self, idx):
        ''' Get a ngram or a range of ngrams

            >>> s = B(b'ABCDEF').ngrams(3)
            >>> s
            ['ABC', 'BCD', 'CDE', 'DEF']

            >>> s[-4], s[-3], s[-2], s[-1], s[0], s[1], s[2], s[3]
            ('ABC', 'BCD', 'CDE', 'DEF', 'ABC', 'BCD', 'CDE', 'DEF')

            >>> s[:2], s[-3:-1]
            (['ABC', 'BCD'], ['BCD', 'CDE'])

            >>> s[:]
            ['ABC', 'BCD', 'CDE', 'DEF']

            '''
        base_slice = self._base_slice_from_ngram_slice(idx)
        if isinstance(idx, slice):
            return self.base[base_slice].ngrams(self.n)

        return self.base[base_slice]

    def __len__(self):
        return len(self.base) - self.n + 1

    def _base_slice_from_ngram_slice(self, idx):
        n = self.n
        start, stop, step = indices_from_slice_or_index(
            idx, len(self), step_must_be_one=True
        )
        return slice(start, stop + n - 1, 1)

    def __repr__(self):
        return repr(list(self))


class NblocksView(SequenceStatsMixin):
    ''' N-blocks view of a byte string.

        A n-block is a sequence of n bytes that do not overlap
        each other.

            >>> s = B('ABCDE')
            >>> nblocks = s.nblocks(3)

            >>> nblocks
            ['ABC', 'DE']

        This also support some basic statistics:

            >>> nblocks = B('ABABCABAABBA').nblocks(2)
            >>> nblocks.freq()
            Counter({'AB': 3, 'BA': 2, 'CA': 1})

            >>> nblocks.most_common(n=2)
            ('AB', 'BA')

            >>> nblocks.entropy()
            1.0114042647073<...>

    '''
    __slots__ = ('base', 'bz')

    def __init__(self, base, block_size):
        if block_size <= 0:
            raise ValueError("The size of a block cannot be zero or negative.")
        self.base = base
        self.bz = block_size

    def __iter__(self):
        bz = self.bz
        return (self.base[i * bz:(i + 1) * bz] for i in range(len(self)))

    def __getitem__(self, idx):
        ''' Get a particular block:

            >>> nblocks = B('ABCDEFGHIJKL').nblocks(4)
            >>> nblocks[-3], nblocks[-1], nblocks[0], nblocks[1], nblocks[2]
            ('ABCD', 'IJKL', 'ABCD', 'EFGH', 'IJKL')

            >>> nblocks
            ['ABCD', 'EFGH', 'IJKL']

            Slices are supported too:

            >>> nblocks[1:2]
            ['EFGH']

            >>> nblocks[0:-1]
            ['ABCD', 'EFGH']

            >>> nblocks[-1:0]
            []

            However, slices with a step or stride different of 1 are not
            supported:

                >>> nblocks[::2]
                Traceback<...>
                IndexError: A slice with a step/stride different of 1 is not supported

            '''
        base_slice = self._base_slice_from_block_slice(idx)
        if isinstance(idx, slice):
            return self.base[base_slice].nblocks(self.bz)

        return self.base[base_slice]

    def __setitem__(self, idx, val):
        ''' Modify a block or a range of blocks.

            >>> s = B(b'ABCDEFGHIJKL', mutable=True).nblocks(4)

            >>> s[0] = B(b'1234')
            >>> s[1:2] = [B(b'5678')]

            >>> s
            ['1234', '5678', 'IJKL']

            >>> s[-3:-1] = [[65, 66, 67, 68], B(b'QWER')]
            >>> s
            ['ABCD', 'QWER', 'IJKL']

            >>> s[:-1] = B(b'12345678', mutable=True).nblocks(4)
            >>> s
            ['1234', '5678', 'IJKL']

            Shorter or larger blocks will not work
            >>> s[0] = B(b'A')
            Traceback<...>
            ValueError: Mismatch lengths, setting 1 bytes into a buffer of 4 bytes length

            With the exception of the last block which may be shorter, but
            still it must have the correct length

            >>> q = B(b'ABCD', mutable=True).nblocks(3)
            >>> q[-1]
            'D'

            >>> q[-1] = B('X')
            >>> q
            ['ABC', 'X']

            In the case of a slice of blocks, the new slice must
            also have the correct length:

            >>> s[:-1] = [B(b'QWER')]
            Traceback<...>
            ValueError: Mismatch lengths, setting 1 blocks into a buffer of 2 blocks length
            '''

        base_slice = self._base_slice_from_block_slice(idx)
        if isinstance(idx, slice):
            nblock_span = (base_slice.stop - base_slice.start) // self.bz
            if nblock_span != len(val):
                raise ValueError("Mismatch lengths, setting %i blocks into a buffer of %i blocks length" \
                        % (len(val), nblock_span))

            for i, block in enumerate(val, base_slice.start // self.bz):
                self[i] = block

        else:
            self.base[base_slice] = val

        return self

    def _base_slice_from_block_slice(self, idx):
        bz = self.bz
        start, stop, step = indices_from_slice_or_index(
            idx, len(self), step_must_be_one=True
        )
        return slice(start * bz, stop * bz, 1)

    def __repr__(self):
        return repr(list(self))

    def __len__(self):
        ''' The length of the block sequence:
            >>> len(B('ABCDEFGHIJKL').nblocks(4))
            3

            If the sequence is not multiple of the block size, the last
            block will have less items:

            >>> b = B('ABCDEFGHIJKL').nblocks(5)
            >>> len(b)
            3

            >>> b
            ['ABCDE', 'FGHIJ', 'KL']

            '''
        return math.ceil(len(self.base) / self.bz)

    def copy(self):
        return self.base.copy().nblocks(self.bz)
