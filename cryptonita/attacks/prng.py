'''
>>> # Convenient definitions
>>> from cryptonita import B        # byexample: +timeout=10
'''


def inv_right_shift(v, b, m):
    '''
        >>> from cryptonita.attacks.prng import inv_right_shift

        >>> y, b, m = 524889969, 11, 0x010101
        >>> v = y ^ ((y >> b) & m)

        >>> inv_right_shift(v, b, m)
        524889969

        >>> y, b, m = 0xffffffff, 4, 0xffffffff
        >>> v = y ^ ((y >> b) & m)

        >>> inv_right_shift(v, b, m)
        4294967295
    '''
    assert 0 < b < 32

    g = 0
    i = 0
    while i < 32:
        g = v ^ ((g >> b) & m)
        i += b

    return g


def inv_left_shift(v, b, m):
    '''
        >>> from cryptonita.attacks.prng import inv_left_shift

        >>> y, b, m = 524889969, 3, 0x010101
        >>> v = y ^ ((y << b) & m)

        >>> inv_left_shift(v, b, m)
        524889969

        >>> y, b, m = 0xffffffff, 4, 0xffffffff
        >>> v = y ^ ((y << b) & m)

        >>> inv_left_shift(v, b, m)
        4294967295
    '''
    assert 0 < b < 32

    g = 0
    i = 0
    while i < 32:
        g = v ^ ((g << b) & m)
        i += b

    return g


def clone_mt19937(out):
    ''' Clone the internal state of a Mersenne Twister 19937 (MT19937)
        from its output <out>.

        For MT19937 we need 624 sequential numbers at minimum to clone
        the state.

            >>> from cryptonita.attacks.prng import clone_mt19937
            >>> clone_mt19937([1, 2, 3])           # byexample: +norm-ws
            Traceback <...>
            ValueError: You need at least 624 numbers to clone the MT19937 PRNG
                        but you have only 3.
        '''

    n = 624
    if len(out) < n:
        raise ValueError(("You need at least %i numbers to clone the MT19937 PRNG" +\
                          " but you have only %i.") % (n, len(out)))

    u, d = 11, 0xffffffff
    s, b = 7, 0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18

    state = []
    for y in out:
        assert isinstance(y, int)
        y = inv_right_shift(y, l, 0xffffffff)  # inv of y ^ ((y >> l) & 0)
        y = inv_left_shift(y, t, c)  # inv of y ^ ((y << t) & c)
        y = inv_left_shift(y, s, b)  # inv of y ^ ((y << s) & b)
        y = inv_right_shift(y, u, d)  # inv of y ^ ((y >> u) & d)

        state.append(y)

    g = MT19937(0)
    g.reset_state(state[:n], index=n)

    return g


# https://en.wikipedia.org/wiki/Mersenne_Twister
class MT19937:
    def __init__(self, seed):
        w, n, m, r = 32, 624, 397, 31
        a, f = 0x9908b0df, 1812433253
        W = 0xffffffff
        u, d = 11, 0xffffffff
        s, b = 7, 0x9d2c5680
        t, c = 15, 0xefc60000
        l = 18

        # Create a length n array to store the state of the generator
        self.MT = MT = []  # n size
        self.index = n + 1
        lower_mask = (1 << r) - 1
        upper_mask = (~lower_mask) & W

        # Initialize the generator from a seed
        index = n
        MT.append(seed)
        for i in range(1, n):
            MT.append((f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i) & W)

        # Generate the next n values from the series x_i
        def twist():
            for i in range(n):
                x = (MT[i] & upper_mask) \
                          + (MT[(i+1) % n] & lower_mask)

                xA = x >> 1
                if (x % 2) != 0:  # lowest bit of x is 1
                    xA = xA ^ a

                MT[i] = MT[(i + m) % n] ^ xA

            self.index = 0

        # Extract a tempered value based on MT[index]
        # calling twist() every n numbers
        def extract_number():
            while 1:
                if self.index >= n:
                    twist()

                y = MT[self.index]
                y = y ^ ((y >> u) & d)
                y = y ^ ((y << s) & b)
                y = y ^ ((y << t) & c)
                y = y ^ (y >> l)

                self.index += 1
                yield y & W

        self.extract_number = extract_number

    def reset_state(self, MT, index=0):
        assert len(MT) == len(self.MT)

        self.index = index
        if not (0 <= self.index <= len(MT)):
            raise IndexError("Setting index=%i is out of range" \
                    % (self.index))

        self.MT[:] = MT

    def __iter__(self):
        return self.extract_number()
