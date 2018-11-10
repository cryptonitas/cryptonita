import collections

def are_same_length_or_fail(a, b):
    if len(a) != len(b):
        raise ValueError("Mismatch lengths. Left string has %i bytes but right string has %i." % \
                            (len(a), len(b)))

def are_bytes_or_fail(val, name):
    if not isinstance(val, collections.ByteString):
        raise TypeError("The parameter '%s' should be a bytes-like instance but it is %s." % \
                            (name, type(val)))


