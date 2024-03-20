def prefix_key_hash(hash_fun, key, message, *hash_args):
    ''' Compute H(k || m)'''
    m = key + message
    return hash_fun(m, *hash_args)


def posfix_key_hash(hash_fun, key, message, *hash_args):
    ''' Compute H(m || k)'''
    m = message + key
    return hash_fun(m, *hash_args)
