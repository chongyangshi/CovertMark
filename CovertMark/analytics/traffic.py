from analytics import constants, entropy
import data.utils

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
    a certain difference (bandwidth), and return descending ordered clusters.
    This is useful if the PT sends a lot of unidirectional equal or similar
    length payloads, for which the traces should have been filtered by source or
    destination IP.
    :param traces: a list of parsed packets, non-tcp packets will be ignored.
    :param tls_only: boolean value that if True ignoring non-TLS frames,
        including TCP frames not containing TLS headers but segmented TLS data.
    :param bandwidth: the maximum distance within clusters, i.e. max difference
        between payload lengths.
    :returns: a list of sets containing clustered values ordered from most
        frequent to least.
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


def ordered_udp_payload_length_frequency(traces, bandwidth=3):
    """
    Utilises meanshift to cluster input udp frames by their packet length to within
    a certain difference (bandwidth), and return descending ordered clusters.
    This is useful if the PT sends a lot of unidirectional equal or similar UDP
    length payloads, for which the traces should have been filtered by source or
    destination IP.
    :param traces: a list of parsed packets, non-udp packets will be ignored.
    :param bandwidth: the maximum distance within clusters, i.e. max difference
        between payload lengths.
    :returns: a list of sets containing clustered values ordered from most
        frequent to least.
    """

    # Collect the lengths.
    lengths = []
    for trace in traces:
        if trace['proto'] != "UDP":
            continue
        else:
            lengths.append(trace['len'])

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


def window_traces_fixed_size(traces, window_size, source_ip=None):
    """
    Segment traces into fixed-trace-size windows, discarding any remainder.
    :param traces: a list of parsed packets.
    :param window_size: a positive integer defining the fixed frame-count of
        each windowed segment, in chronological order.
    :param source_ip: if not None, ignore packets with source not matching the
        source_ip.
    :returns: a 2-D list containing windowed traces.
    """

    if not isinstance(window_size, int) or window_size < 1:
        raise ValueError("Invalid window size.")

    if source_ip is not None:
        trades = list(filter(lambda x: x['src'] == source_ip, traces))

    if len(traces) < window_size:
        return [] # Empty list if insufficient size of input.

    segments = [traces[i:i+window_size] for i in range(0, len(traces), window_size)]

    if len(segments[-1]) != window_size:
        segments = segments[:-1]

    return segments


def window_traces_time_series(traces, chronological_window, sort=True, source_ip=None):
    """
    Segment traces into fixed chronologically-sized windows.
    :param traces: a list of parsed packets.
    :param window_size: a positive integer defining the number of **microseconds**
        covered by each windowed segment, in chronological order.
    :param sort: if True, traces will be sorted again into chronological order,
        useful if packet times not guaranteed to be chronologically ascending.
        True by default.
    :param source_ip: if not None, ignore packets with source not matching the
        source_ip.
    :returns: a 2-D list containing windowed traces.
    """

    if source_ip is not None:
        trades = list(filter(lambda x: x['src'] == source_ip, traces))

    # In Python, even though 'time' is stored as timestap strings by MongoDB,
    # they can be compared as if in float, e.g.:
    # >>> '1518028414.084873' > '1518028414.084874'
    # False
    # Therefore, no explicit conversion is required for sorted(), min() and max().

    # Sorted by time if required.
    if sort:
        traces = sorted(traces, key=itemgetter('time'))

    # Convert to microseconds then integer timestamps, and move to zero
    # for performance.
    min_time = int(float(min(traces, key=itemgetter('time'))['time']) * 1000000)
    max_time = int(float(max(traces, key=itemgetter('time'))['time']) * 1000000)
    start_time = 0
    end_time = max_time - min_time
    if (max_time - min_time) < chronological_window:
        return [] # Empty list if trace duration too small.

    ts = [(t, t+chronological_window) for t in range(start_time, end_time, chronological_window)]
    segments = [[] for i in ts]
    c_segment = 0
    c_segment_max = len(ts) - 1

    for trace in traces:
        trace_t = float(trace['time']) * 1000000 - min_time # Same movement as done above.
        while (not ts[c_segment][0] <= trace_t < ts[c_segment][1]) and (c_segment < c_segment_max):
            c_segment += 1
        segments[c_segment].append(trace)

    return segments
