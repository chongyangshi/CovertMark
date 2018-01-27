from analytics import constants

import scipy.stats
import numpy.random
from math import log
from os import urandom

def byte_entropy(input_bytes):
    """
    Calculate the shannon entropy of the input bytes.
    :param input_bytes: input in bytes.
    :returns: the base 2 shannon entropy of input_bytes.
    """

    if not isinstance(input_bytes, bytes):
        return None

    byte_array = [input_bytes[i:i+1] for i in range(len(input_bytes))]
    occurances = {}
    total = 0
    for s in byte_array:
        if s in occurances:
            occurances[s] += 1
        else:
            occurances[s] = 1
        total += 1

    probabilities = {}
    for occurance in occurances:
        probabilities[occurance] = float(occurances[occurance]) / float(total)

    entropy = 0
    for p in probabilities:
        entropy += -1 * probabilities[p] * log(probabilities[p], 2)

    return entropy


def anderson_darling_dist_test(input_bytes, block_size):
    """
    Perform an Anderson-Darling distribution hypothesis test on whether the
    input_bytes was likely drawn from the same distribution as a random
    distribution, based on Shannon entropy of individual blocks of block_size.
    Raises an exception if input_bytes is insufficient to be divided by
    block_size.
    :param input_bytes: input in bytes to be tested.
    :param block_size: an integer block size for entropy-calculation block.
    :returns {min_threshold, p}, where min_threshold is
        the minimum threshold in float under which the null hypothesis can
        be rejected, between 0.25 and 0.01, 1 if non-rejectable (definitely
        from random distribution), and 0 if always rejectable (definitely
        not from random distribution); and p is the p-value from the test.
    """

    if not isinstance(input_bytes, bytes) or not isinstance(block_size, int):
        raise TypeError("input_bytes must be in bytes and block_size must be an integer.")

    if len(input_bytes) < block_size:
        raise ValueError("Block size is greater than the amount of bytes input.")

    # Chop up the input.
    remainders = len(input_bytes) % block_size
    if remainders > 0: # in Python a[:-0] will result in an empty string.
        input_bytes = input_bytes[:-remainders]
    blocks = [input_bytes[i:i+block_size] for i in range(0, len(input_bytes), block_size)]

    # Calculate each block's entropy as well as a uniform random distribution's.
    block_entropies = [byte_entropy(block) for block in blocks]
    random_entropies = [byte_entropy(numpy.random.bytes(block_size)) for block in blocks]

    # Compare them with Anderson-Darling.
    try:
        statistic, criticals, p = scipy.stats.anderson_ksamp([block_entropies, random_entropies])
    except ValueError:
        return {'min_threshold': 1, 'p': None}
        # Non-rejectable if two distributions are exactly the same, which triggers
        # ValueError in scipy.

    results = {'p': p}

    # Special cases.
    if statistic < criticals[0]:
        results['min_threshold'] = 1 # Non-rejectable null hypothesis.
    elif statistic > criticals[-1]:
        results['min_threshold'] = 0 # Always rejectable null hypothesis.
    else:
        for i in range(len(criticals)-1):
            if statistic >= criticals[i] and statistic <= criticals[i+1]:
                results['min_threshold'] = constants.A_D_THRESHOLDS[i]
                # Rejection threshold.
                break

    # Should never happen unless scipy somehow returns a non-monotonically
    # increasing critical level with a realistic statistic.
    if 'min_threshold' not in results:
        results['min_threshold'] = -1

    return results


def kolmogorov_smirnov_dist_test(input_bytes, block_size):
    """
    Perform a Kolmogorov-Smirnov distribution hypothesis test on on whether the
    input_bytes was likely drawn from the same distribution as a random
    distribution, based on Shannon entropy of individual blocks of block_size.
    Raises an exception if input_bytes is insufficient to be divided by
    block_size.
    :param input_bytes: input in bytes to be tested.
    :param block_size: an integer block size for entropy-calculation block.
    :returns p: the p-value from the KS two-sample test, hypothesis rejectable
        if p is very small (usually <0.1), meaning that likely drawn from non-
        uniform distribution.
    """

    if not isinstance(input_bytes, bytes) or not isinstance(block_size, int):
        raise TypeError("input_bytes must be in bytes and block_size must be an integer.")

    if len(input_bytes) < block_size:
        raise ValueError("Block size is greater than the amount of bytes input.")

    # Chop up the input into equal chunks, discarding remainder.
    remainders = len(input_bytes) % block_size
    if remainders > 0: # in Python a[:-0] will result in an empty string.
        input_bytes = input_bytes[:-remainders]
    blocks = [input_bytes[i:i+block_size] for i in range(0, len(input_bytes), block_size)]

    # Calculate each block's entropy as well as a uniform random distribution's.
    block_entropies = [byte_entropy(block) for block in blocks]
    random_entropies = [byte_entropy(numpy.random.bytes(block_size)) for block in blocks]

    # Perform the KS 2-sample test.
    statistic, p = scipy.stats.ks_2samp(block_entropies, random_entropies)

    return p


# TODO: move this to a proper test.
if __name__ == "__main__":
    print("Testing with uniformly random blocks, should always return high thresholds:")
    test_bytes = urandom(2048)
    for i in range(1, 11):
        b_size = 2 ** i
        result1 = anderson_darling_dist_test(test_bytes, b_size)
        result2 = kolmogorov_smirnov_dist_test(test_bytes, b_size)
        print("Anderson-Darling with block size {} gives min threshold {}, p = {}".format(b_size, result1['min_threshold'], result1['p']))
        print("Kolmogorov-Smirnov with block size {} gives p = {}".format(b_size, result2))

    print()
    print("Testing with a non-random block, should always return a low threshold:")
    test_bytes = "aabcbcabcbcabacbbcabcbcabacbcabbbcabcbcabbacbcbbcabcbcabacbabcbacabcbc".encode('utf-8')
    result1 = anderson_darling_dist_test(test_bytes, 4)
    result2 = kolmogorov_smirnov_dist_test(test_bytes, 4)
    print("Anderson-Darling with block size {} gives min threshold {}, p = {}".format(4, result1['min_threshold'], result1['p']))
    print("Kolmogorov-Smirnov with block size {} gives p = {}".format(4, result2))
