from cryptonita.deps import importdep

np = importdep('numpy')
gp = importdep('gmpy2')
'''
>>> import numpy as np
>>> import gmpy2 as gp

>>> from cryptonita.mod import inv_matrix        # byexample: +timeout=10
'''


def inv_matrix(A, m):
    ''' Find the inverse of the matrix A module m if such exists.

        >>> A = [[2, 4,  5],
        ...      [9, 2,  1],
        ...      [3, 17, 7]]

        >>> inv_A = inv_matrix(A, m=26)

        >>> np.dot(A, inv_A) % 26
        array([[1, 0, 0],
               [0, 1, 0],
               [0, 0, 1]])
        '''

    det_A = np.linalg.det(A)
    inv_A = np.linalg.inv(A)

    # Adjugate matrix of A
    # https://en.wikipedia.org/wiki/Adjugate_matrix
    adj_A = det_A * inv_A

    tmp = np.round(det_A)
    #np.isclose(det_A, tmp)
    det_A = int(tmp)

    inv_det_A = int(gp.invert(det_A, m))

    inv_A = adj_A * inv_det_A
    inv_A = np.round(inv_A)
    return inv_A.astype(int) % m
