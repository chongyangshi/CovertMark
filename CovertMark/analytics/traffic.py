from analytics import constants, entropy

import numpy as np
from scipy import stats
from sklearn.cluster import MeanShift, estimate_bandwidth
from operator import itemgetter

"""
Record and analyse windowed and non-windowed packet flow statistics.
"""

def ordered_tcp_payload_length_frequency(traces, tls_only=False, bandwidth=3):
    """
    Utilises meanshift to cluster input tcp frames by their payload to within
    a certain difference (bandwidth), and return up to top five clusters.
    This is useful if the PT sends a lot of unidirectional equal or similar
    length payloads, for which the traces should have been filtered by source or
    destination IP.
    :param trace: a list of parsed packets, non-tcp packets will be ignored.
    :param tls_only: boolean value that if True ignoring non-TLS frames,
        including TCP frames not containing TLS headers but segmented TLS data.
    :param bandwidth: the maximum distance within clusters, i.e. max difference
        between payload lengths.
    :returns: a list of sets containing values in up to five top clusters.
    """

    # Collect the lengths.
    lengths = []
    for trace in traces:
        if trace['tcp_info'] is None:
            continue
        elif tls_only and trace['tls_info'] is None:
            continue
        else:
            lengths.append(len(trace['tcp_info']['payload']))

    # Cluster the lengths.
    lengths = np.array(list(zip(lengths, np.zeros(len(lengths)))), dtype=np.int)
    meanshift = MeanShift(bandwidth=bandwidth, bin_seeding=True)
    meanshift.fit(lengths)
    labels = meanshift.labels_
    labels_unique = np.unique(labels)
    n_clusters_ = len(labels_unique)

    # Return the top clusters in order.
    clusters = []
    for i in range(n_clusters_):
        members = (labels == i)
        clusters.append(set(lengths[members, 0]))

    return clusters
