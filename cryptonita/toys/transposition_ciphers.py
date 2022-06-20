from cryptonita import B
import string
'''
>>> from cryptonita import B                    # byexample: +timeout=10
>>> from cryptonita.toys.transposition_ciphers import *
'''


def railfence(ptext, key, dec=False):
    ''' Distribute the text in a number of rows or rails and combine
        them in a round-robin-like fashion to generate the ciphertext.

        For example, the combination for a key=4 (four rails) is:

        plaintext = thX_rail_fence
        rail 0      t     i     c     =>  tic
        rail 1       h   a l   n e    =>  halne
        rail 2        X r   _ e       =>  Xr_e
        rail 3         _     f        =>  _f

        Notice the zigzag movement from the rail 0 to the rail 3 and
        to the rail 0 again.

        >>> text = B('the rail fence cipher is a form of transposition cipher')
        >>> railfence(text, 3)
        'tr cir oorpt hh alfnecpe safr ftasoiincpeeie hi m nsoir'

        >>> railfence(text, 4)
        'tich mrs rhalnepesar taoinceer e iri oo nptoih fc ffsip'

        >>> railfence(text, 5)
        't i op hlfcpsa fsonceie hi m nsoir anee frtaiipercrorth'

        >>> railfence(text, 6)
        'termpihfne r socpe chioons h lepsffaineri i   rtoracati'

        >>> ctext = B('termpihfne r socpe chioons h lepsffaineri i   rtoracati')
        >>> railfence(ctext, 6, dec=True) == text
        True
    '''
    if key < 2:
        raise ValueError("Invalid key")

    if dec:

        # this is a hack, we rebuild the rail distribution
        # as if we were encrypting a dummy message of the same
        # length than the original just to know how many
        # items would be in each rail
        # i'm sure that there must be a better way of doing this...
        virtual_rails = [[] for _ in range(key)]
        virtual_rails.extend(reversed(virtual_rails[1:-1]))

        vlen = key + (key - 2)
        assert len(virtual_rails) == vlen
        for i in range(len(ptext)):
            virtual_rails[i % vlen].append(i)  # dummy/placeholders

        # now we replace our placeholders by the real ciphertext
        rails = virtual_rails[:key]
        start = 0
        for i in range(key):
            l = len(rails[i])
            rails[i] = list(ptext[start:start + l])
            start += l

        # and finally we iterate the rails like if we were encrypting
        # but instead of writing (append) we read (pop)
        virtual_rails = rails
        virtual_rails.extend(reversed(virtual_rails[1:-1]))

        tmp = []
        assert len(virtual_rails) == vlen
        for i in range(len(ptext)):
            tmp.append(virtual_rails[i % vlen].pop(0))

        return B(tmp)

    else:
        # we create the n rails (key==n)
        virtual_rails = [[] for _ in range(key)]

        # but we also extend them with n-2 "virtual" rails
        # because Python uses references,
        # the virtual_rails[1] is the same list that virtual_rails[-2],
        # the virtual_rails[2] is the same list that virtual_rails[-3],
        # and so on
        # so adding a symbol to virtual_rails[-2] is like adding the
        # symbol to virtual_rails[1]
        virtual_rails.extend(reversed(virtual_rails[1:-1]))

        vlen = key + (key - 2)
        assert len(virtual_rails) == vlen
        for i, b in enumerate(ptext):
            virtual_rails[i % vlen].append(b)

        # get the first n rails which are the real ones
        # and build the ciphertext from them
        rails = virtual_rails[:key]
        rails = (B(rail) for rail in rails)

        return B.join(rails)
