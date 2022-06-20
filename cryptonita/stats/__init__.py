import math


def _py_entropy(pk, qk=None, base=None):
    '''
        >>> from cryptonita.stats import _py_entropy    # byexample: +timeout=10

        Input normalized
        >>> _py_entropy([0.3, 0.5, 0.2])
        1.0296530140645<...>

        Input not normalized
        >>> _py_entropy([1.3, 2.5, 3.2])
        1.0382125826451<...>

        Different log base (e by default)
        >>> _py_entropy([1.3, 2.5, 3.2], base=7)
        0.5335357252487<...>

        Two inputs (Kullback-Leibler divergence)
        >>> _py_entropy([0.3, 0.5, 0.2], [0.1, 0.1, 0.8])
        0.8570437705935<...>

        Two inputs: not normalized - normalized
        >>> _py_entropy([1.3, 2.5, 3.2], [0.1, 0.1, 0.8])
        0.3137706627238<...>

        Two inputs: normalized - not normalized
        >>> _py_entropy([0.3, 0.5, 0.2], [1.1, 2.1, 3.8])
        0.24969519533828<...>

        Two inputs: different base.
        >>> _py_entropy([1.3, 2.5, 3.2], [0.1, 0.1, 0.8], base=7)
        0.1612462234580<...>

    '''
    log = math.log
    if base == None:
        base = math.e

    if qk == None:
        np = sum(pk)
        return log(np, base) - sum((p * log(p, base)) for p in pk) / np
    else:
        np = sum(pk)
        nq = sum(qk)
        return -log(np / nq, base) + sum(
            (p * log(p / q, base)) for p, q in zip(pk, qk)
        ) / np


try:
    from scipy.stats import entropy
except ImportError:
    entropy = _py_entropy
