import collections

def are_same_length_or_fail(a, b):
    if len(a) != len(b):
        raise ValueError("Mismatch lengths. Left string has %i bytes but right string has %i." % \
                            (len(a), len(b)))

def are_bytes_or_fail(val, name):
    if not isinstance(val, collections.ByteString):
        raise TypeError("The parameter '%s' should be a bytes-like instance but it is %s." % \
                            (name, type(val)))

def indices_from_slice_or_index(idx, l, step_must_be_one):
    if isinstance(idx, slice):
        start, stop, step = idx.indices(l)
        if step != 1 and step_must_be_one:
            raise IndexError("A slice with a step/stride different of 1 is not supported")

    elif isinstance(idx, int):
        # if idx is -1, the naive stop (idx+1) would be 0 which
        # is interpreted as "first block" and not "the last block"
        # which it is what the user wants
        tmp = slice(idx, idx+1 if idx != -1 else l)
        start, stop, step = tmp.indices(l)
    else:
        raise IndexError("Invalid object as index; expected a number or a slice but %s was found" \
                % type(idx))

    # it is guaranteed that the start, stop and step are positives
    return start, stop, step
