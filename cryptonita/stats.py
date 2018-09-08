import collections

class SequenceStatsMixin:
    def freq(self):
        return collections.Counter(self)

    def most_common(self, n):
        elems, _ = zip(*self.freq().most_common(n))
        return elems

