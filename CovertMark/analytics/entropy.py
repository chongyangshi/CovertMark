from analytics import constants

import scipy.stats
import numpy.random
from math import log
from os import urandom

class EntropyAnalyser:

    def __init__(self):
        self.random_bytes = numpy.random.bytes(constants.INITIAL_RANDOM_BLOCK_COUNT)

    def request_random_bytes(self, request_size, block_size):
        """
        It is computationally bottlenecking to generate fresh uniform distributions
        each time a block is analysed, therefore a constant uniformly distributed
        sample is kept, unless enlargement required due to request size.
        :param request_size: an integer representing the size of requested uniformly
            distributed bytes.
        :param block_size: the number of bytes in each block.
        :returns: list of blocks of uniformly distributed bytes of the size
            required.
        """

        if request_size < 1 or not isinstance(request_size, int):
            raise ValueError("Request size must be a positive integer.")

        if not isinstance(block_size, int) or block_size > request_size:
            raise ValueError("Block size must be a positive integer and smaller than request size.")

        if request_size <= len(self.random_bytes):
            requested_bytes = self.random_bytes[:request_size]
        else:
            self.random_bytes = numpy.random.bytes(request_size)
            requested_bytes = self.random_bytes

        blocks = [requested_bytes[i:i+block_size] for i in range(0, len(requested_bytes), block_size)]

        return blocks


    @staticmethod
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


    def anderson_darling_dist_test(self, input_bytes, block_size):
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
        block_entropies = [self.byte_entropy(block) for block in blocks]
        random_entropies = [self.byte_entropy(block) for block in self.request_random_bytes(len(input_bytes), block_size)]

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


    def kolmogorov_smirnov_dist_test(self, input_bytes, block_size):
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
        block_entropies = [self.byte_entropy(block) for block in blocks]
        random_entropies = [self.byte_entropy(block) for block in self.request_random_bytes(len(input_bytes), block_size)]

        # Perform the KS 2-sample test.
        statistic, p = scipy.stats.ks_2samp(block_entropies, random_entropies)

        return p


    def kolmogorov_smirnov_uniform_test(self, input_bytes):
        """
        Perform a Kolmogorov-Smirnov distribution hypothesis test on on whether the
        input_bytes was likely uniformly distributed (not by entropy value).
        :param input_bytes: input in bytes to be tested.
        :returns p: the p-value from the KS two-sample test, hypothesis rejectable
            if p is very small (usually <0.1), meaning input likely not uniformly
            distributed.
        """

        if not isinstance(input_bytes, bytes):
            raise TypeError("input_bytes must be in bytes.")

        # Perform the KS uniform distribution test.
        statistic, p = scipy.stats.kstest(list(input_bytes),
         scipy.stats.uniform(loc=min(input_bytes), scale=max(input_bytes)).cdf)

        return p


# TODO: move this to a proper test.
if __name__ == "__main__":

    test_analyser = EntropyAnalyser()

    print("Testing with uniformly random blocks, should always return high thresholds:")
    test_bytes = urandom(2048)
    for i in range(2, 7):
        b_size = 2 ** i
        result1 = test_analyser.anderson_darling_dist_test(test_bytes, b_size)
        result2 = test_analyser.kolmogorov_smirnov_dist_test(test_bytes, b_size)
        print("Anderson-Darling with block size {} gives min threshold {}, p = {}".format(b_size, result1['min_threshold'], result1['p']))
        print("Kolmogorov-Smirnov with block size {} gives p = {}".format(b_size, result2))

    print()
    result3 = test_analyser.kolmogorov_smirnov_uniform_test(test_bytes)
    print("Kolmogorov-Smirnov byte uniformity test gives p = {}".format(result3))

    print()
    print("Testing with a non-random block, should always return a low threshold:")
    test_bytes = "aabcbcabcbcabacbbcabcbcabacbcabbbcabcbcabbacbcbbcabcbcabacbabcbacabcbc".encode('utf-8')
    result1 = test_analyser.anderson_darling_dist_test(test_bytes, 4)
    result2 = test_analyser.kolmogorov_smirnov_dist_test(test_bytes, 4)
    result3 = test_analyser.kolmogorov_smirnov_uniform_test(test_bytes)
    print("Anderson-Darling with block size {} gives min threshold {}, p = {}".format(4, result1['min_threshold'], result1['p']))
    print("Kolmogorov-Smirnov with block size {} gives p = {}".format(4, result2))
    print("Kolmogorov-Smirnov byte uniformity test gives p = {}".format(result3))
