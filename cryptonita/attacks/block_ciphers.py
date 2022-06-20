from cryptonita import B


def decrypt_ecb_tail(alignment, block_size, encryption_oracle, limit=None):
    align_test_block = B("A" * alignment)

    test_block = B("A" * (block_size - 1))
    align_target_block = B(test_block)  # copy
    distance = 0

    decrypted_bytes = []
    i = 0
    eof = False
    while not eof and (i < limit if limit else True):
        i += 1
        eof = True
        for b in range(256):
            b = B(b)

            # propose the following choosen plaintext:
            #
            #   |-------|-------|-------|------
            #    ....AAA AAAAAAb AAAAAA? .....
            #       |       |       |
            #       |       |  a block identical to the test block except
            #       |       |  the last byte that's unknow to us (to be decypted)
            #       |  a "test" block: a full block where the last byte
            #       |  is our guessed byte (if 'b' is equal to '?' our guess is correct)
            #    padding block for alignment purposes
            tmp = align_test_block + test_block + b + align_target_block
            c = encryption_oracle(tmp)

            # TODO i'm not resistent to possible false positive!
            if c.nblocks(block_size).has_duplicates(distance):
                # two block had collided to a <distance> blocks of distance
                # that means that out guess 'b' matched with the unknow
                # bytes '?' effectively decrypting it
                eof = False
                decrypted_bytes.append(b)

                # the test block shift to the left one byte, now that we
                # now that 'b' is the correct byte we are reserving one byte
                # on the right for the next guess
                #           |-------|
                #            AAAAAAb  -> b is guessed ok (G)
                #           |-------|
                #            AAAAAAG  -> shift the block to make room
                #           |-------|
                #            AAAAAG   -> the byte missing will be filled
                #                        with the next guess 'b'
                test_block = test_block << b

                if len(align_target_block) == 0:
                    align_target_block = B("A" * (block_size - 1))
                    distance += 1
                else:
                    align_target_block = align_target_block[:-1]

                break

    return B(b''.join(decrypted_bytes))


def decrypt_cbc_last_blk_padding_attack(cblocks, bsize, oracle):
    prev_cblock = cblocks[-2]

    x = B(range(bsize, 0, -1), mutable=True)
    x ^= prev_cblock
    for i in range(bsize - 1, -1, -1):
        prefix = prev_cblock[:i]
        padn = B(bsize - i)
        posfix = B(padn * (bsize - i - 1)) ^ x[i + 1:]

        # forge the penultimate ciphertext block
        cblocks[-2] = B(prefix + B(0) + posfix, mutable=True)
        for n in range(256):
            if prev_cblock[i] == n:
                continue

            # update the forged byte
            cblocks[-2][i] = n
            forged_ciphertext = B('').join(cblocks)

            good = oracle(forged_ciphertext)
            if good:
                x[i] = (padn ^ B(n))
                break

    cblocks[-2] = prev_cblock  # restore backup
    x ^= prev_cblock
    return x  # plain text block


def decrypt_cbc_padding_attack(ciphertext, bsize, oracle, iv=None):
    p = []
    if iv != None:
        ciphertext = iv + ciphertext

    cblocks = list(ciphertext.nblocks(bsize))

    while len(cblocks) > 1:
        p.append(decrypt_cbc_last_blk_padding_attack(cblocks, bsize, oracle))
        del cblocks[-1]

    p.reverse()
    return B('').join(p)
