from math import log


def byte_entropy(input_bytes):
    """
    Calculate the shannon entropy of the input bytes.
    :param input_bytes: input in bytes,
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
