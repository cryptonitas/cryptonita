import math
'''
>>> from cryptonita.stats.distribution_summary import DistributionSummary
'''


class _T:
    __slots__ = ('v', 'g', 'd')

    def __init__(self, v, g, d):
        self.v = v  # value seen from the stream

        # the sum of all g for all the tuples preceeding and including self
        # represent the minimum rank of the value v (rmin)
        #
        # this value is the 'gap' between the current tuple's rmin and
        # the previous tuple's rmin
        self.g = g

        # given rmin, the maximum rank of the value v is rmin + d
        self.d = d

    def __repr__(self):
        return f"({self.v}, {self.g}, {self.d})"

    def __iter__(self):
        return iter((self.v, self.g, self.d))


class DistributionSummary:
    '''
    Implements an e-approximated q-quantile summary based on the work
    of Greenwald and Khanna ([GK01], [GK04]).
    Taken some extra ideas from Luo at et ([LWYC]).

    [GK01] Space-Efficient Online Computation of Quantile Summaries,
    Michael Greenwald, Sanjeev Khanna.

    [LWYC] Quantiles over Data Streams: Experimental Comparisons, New Analyses,
    and Further Improvements.
    Ge Luo, Lu Wang, Ke Yi and Graham Cormode.
    '''
    def __init__(self, epsilon, *, max_buffer_len=1024**2, check_invariants=False):
        if not (0 < epsilon < 1):
            raise ValueError(
                f"Epsilon value '{epsilon}' (error tolerance fraction) must be between 0 and 1."
            )

        self.epsilon = epsilon
        self.max_buffer_len = max_buffer_len
        self.check_invariants = check_invariants

        # Check if we want to use the buffered mode
        self.buffered = max_buffer_len > 1

        # Track how many values we saw so far
        # GK01 algorithm does *not* require to know
        # a priori the total length of the stream
        self.n = 0

        # Track new values here, defering the update of the summary data structure
        # for performance reasons.
        # This is the tweak mentioned in [LWYC], section 2.1.2
        self.buffer = []

        # The 'summary' data structure is a list of tuples (v, g, d)
        # that track a subset of the values seen and implicitly the possible rank
        # of each.
        # This data structure remains sorted by value v;
        self.summary = []

    def add_observation(self, value):
        self.buffer.append(value)

        if self._should_flush():
            self._add_and_compress(self.buffer)
            self.buffer.clear()

    def add_observations(self, values):
        '''
        Add the given observations to the summary.

        In buffered mode, defer the addition to the summary until
        the on-hold observations buffer either reaches the current
        summary size or reaches a maximum (max_buffer_len).

        If a query is made (by rank or quantile) or the min/max/range
        are requested, the on-hold observations are flushed and added
        to the summary before answering so this buffering should not
        alter the results of any query.

        In non-buffered mode, perform the addition of the values immediately.
        '''

        if not self.buffered:
            for v in values:
                self.add_observation(v)
        else:
            self.buffer.extend(values)

            if self._should_flush():
                expected_n = self.n + len(self.buffer)

                i = 0
                n = max(self.n, 2)
                while len(self.buffer) - i > n:
                    self._add_and_compress(self.buffer[i:i + n])
                    i += n  # increment by the old n
                    n = self.n  # the new n

                self.buffer = self.buffer[i:]

                # check that we didn't lost any observation
                assert self.n + len(self.buffer) == expected_n

    def range(self):
        '''
        Return the minimum and the maximum values observed so far.
        '''
        self._flush()
        return self._range()

    def min(self):
        return self.range()[0]

    def max(self):
        return self.range()[-1]

    def median(self):
        '''
        Return the e-approximated 0.5-quantile.
        '''
        return self.quantile(0.5)

    def max_error(self):
        '''
        Return the maximum error that a response for the rank r can have.
        In other words, asking for the rank r will yield a response
        that it is actually rank k with |r - k| <= max_error.

        The max error is defined as floor(n * epsilon)  where n is the count
        of observations seen so far and epsilon the relative error.
        '''
        self._flush()
        return self._max_error()

    def space_metrics(self):
        return f"n: {self.n}  |s|: {len(self.summary)} ({(len(self.summary) / self.n) * 100:.02f}%)  |b|: {len(self.buffer)} ({(len(self.buffer) / self.n) * 100:.02f}%)"

    def observations_count(self):
        # take into consideration any value still in the buffer
        return self.n + len(self.buffer)

    def quantile(self, q):
        '''
        Return the e-approximated quantile.

        The value q must be in the open half (0  1] range.
        '''
        return self.quantiles([q])[0]

    def quantiles(self, quantiles):
        '''
        Return the e-approximated quantiles

        The values must be in the open half (0  1] range.
        '''
        if not quantiles:
            raise ValueError(f"No quantile was provided.")

        for q in quantiles:
            if not (0 < q <= 1):
                raise ValueError(
                    f"Value '{q}' is not valid as a quantile (it should be strictly greater than 0 and less or equal to 1)."
                )

        return self.ranks([math.ceil(q * self.n) for q in quantiles])

    def rank(self, r):
        '''
        Search for the value for the e-approximated rank r.
        The value returned is guaranteed to be in a rank up to ceil(e*n) positions
        from r.

        The value r must be between 1 and n.
        '''
        return self.ranks([r])[0]

    def ranks(self, ranks):
        '''
        Search for the value for the e-approximated rank r.
        The values returned are guaranteed to be in ranks up to ceil(e*n) positions
        from the requested ranks.

        >>> I = [26, 45, 12, 13, 89, 14, 24, 55, 98]
        >>> gk = DistributionSummary(0.1)

        >>> gk.add_observations(I)
        >>> gk.rank(1)
        12

        >>> gk.rank(gk.n)
        98

        >>> gk.ranks([7, 1, 2, 5, 1, 1])
        [55, 12, 13, 26, 12, 12]

        The ranks must be between 1 and n.

        >>> gk.rank(0)
        Traceback <...>
        ValueError: Rank '0' out of range. Valid values are between 1 and 9 (both inclusive).

        >>> gk.rank(gk.observations_count() + 1)
        Traceback <...>
        ValueError: Rank '10' out of range. Valid values are between 1 and 9 (both inclusive).

        >>> gk.ranks([])
        Traceback <...>
        ValueError: No rank was provided.

        There are a few methods as shortcuts for some common ranks:

        >>> gk.min()
        12

        >>> gk.max()
        98

        >>> gk.range()
        (12, 98)

        >>> gk.median()
        26

        '''
        if not ranks:
            raise ValueError(f"No rank was provided.")

        for r in ranks:
            if not 0 < r <= self.observations_count():
                raise ValueError(
                    f"Rank '{r}' out of range. Valid values are between 1 and {self.observations_count()} (both inclusive)."
                )

        # ensure that all the buffered values are added to the summary before continuing
        self._flush()

        # expected answer count
        expected_ans_cnt = len(ranks)

        # answers and answer count
        ans = [0] * expected_ans_cnt
        ans_cnt = 0

        # we answer each requested rank in incresing order to do a single pass
        # over the summary (O(n))
        # attach to each rank its position in the user's input list so we can answer
        # in the same order
        ranks_it = iter(sorted(zip(ranks, range(len(ranks)))))

        # track the 'minimum' rank
        rmin = 0

        # err defined by the epsilon times the number of observations seen so far
        err = self._max_error()

        r, ans_ix = next(ranks_it)
        i = 0
        prev_rmin = 0
        while i < len(self.summary):
            vi, gi, di = self.summary[i]

            rmin = prev_rmin + gi
            rmax = rmin + di

            #    rmin                               rmax
            # ---- | ------------------------------- | ------
            #      :  r-e ( ---  r --- ) r+e         :            bad
            #      :                 r-e ( ---  r --- ) r+e       bad
            # r-e ( --- r --- ) r+e                  :            bad
            #      :                                 :
            #
            #
            #             rmin      rmax
            # ------------- | ------ | -------------
            #         r-e ( ---  r --- ) r+e                      good
            #               :        :
            #
            # In other words, the range defined by r+/-err fully contains
            # the range (rmin rmax)
            if rmin >= r - err and rmax <= r + err:
                ans[ans_ix] = vi
                ans_cnt += 1

                # continue with the next quantile (rank) requested
                # comparing it with the same summary[i] (index i is *not* incremented)
                r, ans_ix = next(ranks_it, (None, None))

                if r is None:
                    # we are done, we answered all the requested quantiles
                    break
            else:
                prev_rmin = rmin
                i += 1

        # We should always find all epsilon-approximated quantiles 'q' requested
        assert expected_ans_cnt == ans_cnt

        # The list contains the answers in the same order than the ranks requested.
        return ans

    @classmethod
    def combine(cls, summary_a, summary_b):
        # Combine 2 Summaries
        # [GK04] Power conserving computation of order-statistics over sensor networks
        raise NotImplemented("Not supported yet")

    def summary_dump(self):
        self._flush()
        ranks_ranges = []
        rmin = 0
        for _, g, d in self.summary:
            rmin += g
            rmax = rmin + d
            ranks_ranges.append(f"[{rmin} {rmax}]")

        values = []
        for (v, _, _), rr in zip(self.summary, ranks_ranges):
            v = str(v).center(len(rr))
            values.append(v)

        ngaps = []
        for (_, g1, d1), (_, g2, d2), rr in zip(self.summary[:-1], self.summary[1:], ranks_ranges):
            c = str(g1 + d1 + g2 + d2 - 1).center(len(rr))
            ngaps.append(c)
        ngaps.append('x'.center(len(ranks_ranges[-1])))

        print(f'n: {self.n}   epsilon: {self.epsilon:.04f}   err: {self._max_error():.04f}')
        print(f'max gap: {2 * self._max_error()}')

        C = 12
        for i in range((len(values) // C) + 1):
            print("values:", ''.join(values[i * C:(i + 1) * C]))
            print("ranks: ", ''.join(ranks_ranges[i * C:(i + 1) * C]))
            print("ngaps: ", ''.join(ngaps[i * C:(i + 1) * C]))
            print()

    def _compress(self):
        '''
        Perform a compression over the current summary without adding any new observation,
        not even if self.buffer is non-empty.
        '''
        self._add_and_compress([])

    def _add_and_compress(self, observations):
        '''
        Add the given observations to the summary and perform
        a compression, trying to reduce the footprint of the summary
        while preserving the e-approximation.
        '''
        observations = list(sorted(observations))

        if self.check_invariants:
            if observations:
                _min_value = observations[0]
                _max_value = observations[-1]

                if self.summary:
                    _min_value = min(_min_value, self.summary[0].v)
                    _max_value = max(_max_value, self.summary[-1].v)
            else:
                if self.summary:
                    _min_value = self.summary[0].v
                    _max_value = self.summary[-1].v

        if not observations and not self.summary:
            # nothing to do actually: no observations to add, no summary to compress
            return

        o = len(observations) - 1
        i = len(self.summary) - 1

        self.n += len(observations)

        new_reversed_summary = []

        # We merge the incoming values in observations with the current summary
        # to get a new summary list.
        # This is the "batch" or "array" mode from [LWYC], section 2.1.2
        #
        # We iterate in parallel for both arrays in 'reverse' or backward
        # direction (from the highest to the lowest values).
        # This is how it is suggested by COMPRESS, see [GW], figure 2.
        while o >= 0 and i >= 0:
            is_the_minimum = o == i == 0
            is_the_maximum = not new_reversed_summary
            is_extreme = is_the_minimum or is_the_maximum

            vo = observations[o]

            vi, gi, di = self.summary[i]

            # We are inserting tuples in new_reversed_summary in reverse order
            # from high values to low values so the next tuple to insert
            # must have a value greater than its competitor
            if vi > vo:
                tnew = self.summary[i]
                i -= 1
            elif vi <= vo:
                do = self._compute_d_for_new_observation(
                    new_reversed_summary, vo, is_extreme=is_extreme
                )
                tnew = _T(vo, 1, do)
                o -= 1
            else:
                assert False

            self._append_tuple(new_reversed_summary, tnew, allow_delete=not is_the_minimum)

        while o >= 0:
            assert i < 0
            is_the_minimum = o == 0
            is_the_maximum = not new_reversed_summary
            is_extreme = is_the_minimum or is_the_maximum

            vo = observations[o]

            do = self._compute_d_for_new_observation(
                new_reversed_summary, vo, is_extreme=is_extreme
            )
            tnew = _T(vo, 1, do)

            self._append_tuple(new_reversed_summary, tnew, allow_delete=not is_the_minimum)

            o -= 1

        while i >= 0:
            assert o < 0
            is_the_minimum = i == 0

            tnew = self.summary[i]
            self._append_tuple(new_reversed_summary, tnew, allow_delete=not is_the_minimum)

            i -= 1

        # Update the new summary
        # Reverse it, keep sorted from min to max values
        self.summary = new_reversed_summary[::-1]

        if self.check_invariants:
            # Invariant check: the summary must track the real count of observations
            assert sum(t.g for t in self.summary) == self.n

            # Invariant check: the error must be below the expected threshold
            assert all(t.g + t.d - 1 <= 2 * self._max_error() for t in self.summary)

            # Check that we preserved the true min/max observed values
            assert self._range() == (_min_value, _max_value)

    def _compute_d_for_new_observation(self, new_reversed_summary, vo, *, is_extreme):
        if is_extreme:
            # Both the minimum and the maximum values will have a d of 0.
            return 0

        # We define the d value of a new tuple (from a new observation in the buffer)
        # as the g+d-1 of the immediately following tuple (here, immediately following
        # means the last appended tuple in new_reversed_summary).
        #
        # If this new tuple is the first tuple, assign d to be zero
        # (actually this is not required as we do this same assignation at the end
        # where both the first and the last tuples of new_reversed_summary will have d == 0)
        #
        # This is the Adaptive version, see [GK01], section 3 and [LWYC], section 2.1.1
        # the '-1' accounts to compensate for the new tuple's g value (1)
        assert new_reversed_summary[-1].v >= vo
        return new_reversed_summary[-1].g + new_reversed_summary[-1].d - 1

    def _append_tuple(self, new_reversed_summary, tnew, allow_delete):
        '''
        Insert the new tuple tnew into the (new)summary.

        If allow_delete is True, we skip the append only if
        we do not leave a gap the exceeds twice the maximum error (_max_error)
        required to keep an e-approximation summary.
        Skipping the new tuple is equivalent to inserting it and immediately
        removing it but it is faster.

        If allow_delete is False, never skip/delete and append the tuple directly.
        This is handy if the caller wants to preserve the last tuple
        (aka, ithe minimum value observed or rank 1) which may be delete (not appended)
        if the conditions are right. Setting allow_delete = False for this case
        prevents us from losing the minimum.
        '''
        if not new_reversed_summary or not allow_delete:
            # nothing to override, do an append directly
            new_reversed_summary.append(tnew)
            return

        err = 2 * self._max_error()

        tlast = new_reversed_summary[-1]
        assert tlast.v >= tnew.v
        if tnew.g + tnew.d + tlast.g + tlast.d - 1 <= err and allow_delete:
            tlast.g += tnew.g
        else:
            new_reversed_summary.append(tnew)

    def _should_flush(self):
        return len(self.buffer) > len(self.summary) or len(self.buffer) >= self.max_buffer_len

    def _flush(self):
        if not self.buffered or not self.buffer:
            return

        self._add_and_compress(self.buffer)
        self.buffer.clear()

    def _max_error(self):
        return math.floor(self.epsilon * self.n)

    def _range(self):
        return self.summary[0].v, self.summary[-1].v
