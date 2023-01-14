from .score_funcs import *

from cryptonita.fuzzy_set import FuzzySet
from cryptonita.helpers import are_bytes_or_fail


def scoring(msg, space, score_func, min_score=0.5, **score_func_params):
    ''' Run the score function over the given message and over a parametric
        value x. Return all the values x as a FuzzySet (guess)
        which scores is greather than the minimum score.

        The parametric space <space> can is defined as:
         - a range object
         - or any other iterable of the parametric values x

        For each possible x, score each using <score_func> and
        drop anyone with a score of <min_score> or less.

        Extra parameters can be passed to the <score_func> using
        <score_func_params>.

        Return a FuzzySet with the x values.
        '''
    assert 0.0 <= min_score <= 1.0
    are_bytes_or_fail(msg, 'msg')

    params = score_func_params
    lengths = FuzzySet(
        ((x, score_func(msg, x, **params)) for x in space),
        pr='tuple',
        min_membership=min_score
    )
    return lengths
