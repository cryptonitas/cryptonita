'''
>>> # Convenient definitions
>>> from cryptonita import B        # byexample: +timeout=10
>>> from cryptonita.space import IntSpace
'''


class IntSpace:
    def __init__(self, a, b=None, step=1, start=None):
        ''' IntSpace defines a space of integers (range) similar to
            Python's range() but with both extremes inclusive

            Defining only one of the extremes sets the upper bound
            so the range is defined as [0 5] (both inclusive)

            >>> list(IntSpace(5))
            [0, 1, 2, 3, 4, 5]

            Defining two extremes you can set the lower an upper bounds

            >>> list(IntSpace(3, 5))
            [3, 4, 5]

            >>> list(IntSpace(5, 5))
            [5]

            >>> list(IntSpace(0))
            [0]

            Like Python's range(), you can define the step however negative
            steps are not allowed.

            >>> list(IntSpace(5, step=2))
            [0, 2, 4]

            >>> list(IntSpace(3, 5, step=2))
            [3, 5]

            >>> list(IntSpace(5, 5, step=2))
            [5]

            >>> list(IntSpace(0, step=2))
            [0]

            In contrast with Python's range(), IntSpace allows to define
            an arbitrary starting point for the iteration.

            For example you can start from the end
            (similar to Python's range(..,.., -1)):

            >>> list(IntSpace(5, start='end'))
            [5, 4, 3, 2, 1, 0]

            Another starting point is the 'middle' point:

            >>> list(IntSpace(5, start='middle'))
            [2, 1, 3, 0, 4, 5]

            Note how the iteration starts from the middle point and goes to each
            extreme alternating between numbers lower and higher.

            The reason behind this is the assumption that numbers near
            the starting points are more interesting than the ones far from it.

            The start is not restricted to those fixed labels: arbitrary numbers
            are allowed:

            >>> list(IntSpace(5, start=1))
            [1, 0, 2, 3, 4, 5]

            >>> list(IntSpace(5, start=3))
            [3, 2, 4, 1, 5, 0]

            >>> list(IntSpace(5, start=4))
            [4, 3, 5, 2, 1, 0]

            The start can be combined with the step

            >>> list(IntSpace(5, start='end', step=2))
            [5, 3, 1]

            >>> list(IntSpace(5, start='middle', step=2))
            [2, 0, 4]

            >>> list(IntSpace(5, start=1, step=2))
            [1, 3, 5]

            >>> list(IntSpace(5, start=3, step=2))
            [3, 1, 5]

            >>> list(IntSpace(5, start=4, step=2))
            [4, 2, 0]

            >>> list(IntSpace(5, start=4, step=3))
            [4, 1]

            Invalid settings:

             - Swapped lower/upper bounds

             >>> IntSpace(-2)
             Traceback<...>
             ValueError: Invalid range [0 a] with a=-2 ('a' must be non-negative)

             >>> IntSpace(5, 2)
             Traceback<...>
             ValueError: Invalid range [a b] with a=5 and b=2 ('a' must be less than or equal to 'b')

             - Non-positive step

             >>> IntSpace(5, step=0)
             Traceback<...>
             ValueError: Invalid step s=0 over range [0 5] ('s' must be positive)

             >>> IntSpace(5, step=-1)
             Traceback<...>
             ValueError: Invalid step s=-1 over range [0 5] ('s' must be positive)

             - Invalid start

             >>> IntSpace(5, start=tuple())
             Traceback<...>
             ValueError: Invalid start s=() over range [0 5]. Expected an integer or the keywords 'begin', 'middle' or 'end'

             >>> IntSpace(5, start='foo')
             Traceback<...>
             ValueError: Invalid start s=foo over range [0 5]. Expected an integer or the keywords 'begin', 'middle' or 'end'

             - Valid start but out of range

             >>> IntSpace(5, start=-1)
             Traceback<...>
             ValueError: The start s=-1 is out of the range [0 5]

             >>> IntSpace(5, start=6)
             Traceback<...>
             ValueError: The start s=6 is out of the range [0 5]
        '''

        if b is None:
            if a < 0:
                raise ValueError(
                    f"Invalid range [0 a] with a={a} ('a' must be non-negative)"
                )
            self.lo, self.hi = 0, a
        else:
            if b < a:
                raise ValueError(
                    f"Invalid range [a b] with a={a} and b={b} ('a' must be less than or equal to 'b')"
                )
            self.lo, self.hi = a, b

        assert self.lo <= self.hi

        if step <= 0:
            raise ValueError(
                f"Invalid step s={step} over range [{self.lo} {self.hi}] ('s' must be positive)"
            )

        self.step = step
        assert self.step >= 1

        if (start != None) and not isinstance(start, int) and start not in (
            "begin", "middle", "end"
        ):
            assert start is not None
            raise ValueError(
                f"Invalid start s={start} over range [{self.lo} {self.hi}]. Expected an integer or the keywords 'begin', 'middle' or 'end'"
            )

        if isinstance(start, int) and (start < self.lo or start > self.hi):
            raise ValueError(
                f"The start s={start} is out of the range [{self.lo} {self.hi}]"
            )

        if start is None or start == "begin":
            start = self.lo
        elif start == 'middle':
            start = ((self.hi + self.lo) // 2)
        elif start == 'end':
            start = self.hi
        else:
            assert isinstance(start, int)

        self.start = start
        assert self.lo <= self.start <= self.hi

    def __iter__(self):
        return self._space_generator()

    def _space_generator(self):
        lo, hi = self.lo, self.hi
        step, start = self.step, self.start

        lower = range(start - step, lo - 1, -step)
        higher = range(start, hi + 1, step)

        # yield alternating higher and lower numbers
        cnt = 0
        for h, l in zip(higher, lower):
            yield h
            yield l
            cnt += 1

        # recreate the ranges but take into account that we already
        # yielded some of them
        hi_start = start + cnt * step
        lo_start = start - (cnt + 1) * step

        # yield the remaining numbers (if any)
        if hi_start <= hi:
            # assert that we couldn't enter in the other if-case
            assert not lo_start >= lo

            higher = range(hi_start, hi + 1, step)
            for h in higher:
                yield h

        elif lo_start >= lo:
            # assert that we couldn't enter in the other if-case
            assert not hi_start <= hi

            lower = range(lo_start, lo - 1, -step)
            for l in lower:
                yield l
