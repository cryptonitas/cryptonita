from cryptonita import B
from cryptonita.stats.distribution_summary import DistributionSummary

import random, math, itertools
import tqdm

BUFFERED = (True, False)
REPETITION_COUNTS = (0, 1, 2, 4)
INPUT_SET_SIZES = (9, -9, -100, 10000, 100000)
EPSILONS = (0.1, 0.5, 0.9, 0.001)
QUANTILES = (0.00000000001, 1)

bar = tqdm.tqdm(total = sum((N + 7 + len(QUANTILES)) * len(EPSILONS) * len(REPETITION_COUNTS) * len(BUFFERED) for N in [input_sz for input_sz in INPUT_SET_SIZES]))
for input_sz in INPUT_SET_SIZES:
    for repetitions in REPETITION_COUNTS:
        rng = random.Random(20241206)
        if input_sz < 0:
            # make the input sorted
            input_sz *= -1
            input_sorted = True
        else:
            input_sorted = False

        I = list(range(1, input_sz+1))
        I = I * (1 + repetitions)

        if input_sorted:
            I.sort()
        else:
            # make the input shuffled random
            rng.shuffle(I)

        I = I[:input_sz]
        sortedI = list(sorted(I))

        for e in EPSILONS:
            for buffered in BUFFERED:
                max_buffer_len = 1024**2 if buffered else 0
                gk = DistributionSummary(e, max_buffer_len=max_buffer_len, check_invariants=True)

                gk.add_observations(I)

                min_val, max_val = gk.range()

                assert min_val == sortedI[0]
                assert max_val == sortedI[-1]

                err_rounded = (2 * e * (gk.n-2)) + 1
                log_err = math.log2(err_rounded)
                err_scalar = 11 / (2 * e)
                expected_max_summary_length =  math.ceil(err_scalar * log_err)

                tolerance = gk.max_error()
                if False: # NOTE DISABLED | not len(gk.summary) <= expected_max_summary_length:
                    print("FAIL: upper bound on summary length failed")
                    print(f"Test n={len(I)} input_sz={input_sz} (repetitions={repetitions}) epsilon={e} sorted={input_sorted} buffered={buffered}")
                    print(f"Summary sz={len(gk.summary)}, err-rounded={err_rounded}, log-err={log_err}")
                    print(f"Expected-max-length={expected_max_summary_length}")
                    print(f"Relative diff (respect expected)={((len(gk.summary) - expected_max_summary_length) / expected_max_summary_length) * 100:.02f}%  Summary length/obs cnt ratio={(len(gk.summary) / gk.n) * 100:.02f}%")


                for r in itertools.chain((1, 2, 3, len(I), len(I)//2, len(I)//4, len(I) - 1), range(1, len(I)+1)):
                    rmin = max(math.floor(r - 1 - tolerance), 1)
                    rmax = max(math.ceil(r - 1 + tolerance), 1) + 1
                    expecteds = sortedI[rmin - 1: rmax] # Python is 0-based indexed and open-ended
                    obtained = gk.rank(r)

                    if obtained not in expecteds:
                        print("FAIL: rank query failed")
                        print(f"Test n={len(I)} input_sz={input_sz} (repetitions={repetitions}) epsilon={e} sorted={input_sorted} buffered={buffered}")
                        print(f"Rank queried: {r}")
                        print(f"With tolerance {tolerance}, expected valid ranks {rmin} to {rmax}")
                        print(f"Obtained value: {obtained}")
                        print(f"Expected valid values: {expecteds}")
                        print("Dump:")
                        gk.summary_dump()
                        print("---------------------------")
                        print()

                    bar.update()

                for q in QUANTILES:
                    r = q * gk.observations_count()
                    rmin = max(math.floor(r - 1 - tolerance), 1)
                    rmax = max(math.ceil(r - 1 + tolerance), 1) + 1
                    expecteds = sortedI[rmin - 1: rmax] # Python is 0-based indexed and open-ended
                    obtained = gk.quantile(q)

                    if obtained not in expecteds:
                        print("FAIL:m quantile query failed")
                        print(f"Test n={len(I)} input_sz={input_sz} (repetitions={repetitions}) epsilon={e} sorted={input_sorted} buffered={buffered}")
                        print(f"Rank queried: {r}")
                        print(f"With tolerance {tolerance}, expected valid ranks {rmin} to {rmax}")
                        print(f"Obtained value: {obtained}")
                        print(f"Expected valid values: {expecteds}")
                        print("Dump:")
                        gk.summary_dump()
                        print("---------------------------")
                        print()

                    bar.update()
bar.close()
