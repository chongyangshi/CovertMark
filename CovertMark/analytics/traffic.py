from analytics import constants, entropy
import data.utils

import numpy as np
from scipy import stats
from sklearn.cluster import MeanShift, estimate_bandwidth
from operator import itemgetter
from collections import Counter, defaultdict

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


def window_traces_fixed_size(traces, window_size):
    """
    Segment traces into fixed-size windows, discarding any remainder.
    :param traces: a list of parsed packets.
    :param window_size: a positive integer defining the fixed frame-count of
        each windowed segment, in chronological order.
    :returns: a 2-D list containing windowed traces.
    """

    if not isinstance(window_size, int) or window_size < 1:
        raise ValueError("Invalid window size.")

    if len(traces) < window_size:
        return [] # Empty list if insufficient size of input.

    segments = [traces[i:i+window_size] for i in range(0, len(traces), window_size)]

    if len(segments[-1]) != window_size:
        segments = segments[:-1]

    return segments


def window_traces_time_series(traces, chronological_window, sort=True):
    """
    Segment traces into fixed chronologically-sized windows.
    :param traces: a list of parsed packets.
    :param window_size: a positive integer defining the number of **microseconds**
        covered by each windowed segment, in chronological order.
    :param sort: if True, traces will be sorted again into chronological order,
        useful if packet times not guaranteed to be chronologically ascending.
        True by default.
    :returns: a 2-D list containing windowed traces.
    """

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


def group_traces_by_ip_fixed_size(traces, clients, window_size):
    """
    Group traces into fixed-size segments that contain bidirectional traffic
    from and towards individual predefined clients, individual inputs should
    normally come from time-windowing by self.window_traces_time_series (e.g. 60s)
    to simulate realistic firewall operation conditions.
    :param traces: a list of parsed packets, packets in the 1D list are assumed
        to be chronologically ordered.
    :param clients: a predefined list of Python subnets objects describing
        clients that are considered within the firewall's control.
    :param window_size: threshold to start a new segment.
    :returns: a dictionary indexed by a tuple of individual client and target pair,
        containing one 2D list for each pair. Each 2D list contains segmented
        traces by fixed size, with remainders retained.
    """

    if len(clients) < 1:
        return []

    client_traces = defaultdict(list)
    for trace in traces:

        trace_srcnet = data.utils.build_subnet(trace['src'])
        trace_dstnet = data.utils.build_subnet(trace['dst'])
        trace_client = None

        for client in clients:
            if client.overlaps(trace_srcnet):
                trace_client = trace_srcnet
                target = trace['dst']
                break

            elif client.overlaps(trace_dstnet):
                trace_client = trace_dstnet
                target = trace['src']
                break

        if not trace_client:
            continue # Irrelevant trace.

        # Append here first.
        client_traces[(str(trace_client), target)].append(trace)

    # Now segment for each client/target pair by fixed size.
    for c in client_traces:
        client_traces[c] = [client_traces[c][i:i+window_size] for i in range(0, len(client_traces[c]), window_size)]
        if len(client_traces[c][-1]) < window_size: # Discard remainder.
            client_traces[c] = client_traces[c][:-1]

    return client_traces


def get_window_stats(windowed_traces, client_ips, feature_selection=None):
    """
    Calculate the following features for the windowed traces:
        {
            'mean_entropy_up': mean entropy of upstream TCP payloads;
            'mean_interval_up': upstream mean TCP ACK intervals;
            'bin_#_interval_up': the number of in-range intervals between TCP frames,
                ranges divided between 0, 1000, 10000, 100000, 1000000 microseconds,
                with value represented as the upper range of each interval. Only
                the first of all frames bearing the unique sequence number is
                 counted;
            'top1_tcp_len_up': the most common upstream TCP payload length;
            'top2_tcp_len_up': the second most common upstream TCP payload length;
            'mean_tcp_len_up': mean upstream TCP payload length.
            'push_ratio_up': ratio of TCP ACKs with PSH flags set, indicating
                reuse of TCP handshake for additional data;
            (All attributes above, except for downstream and named '..._down');
            'up_down_ratio': ratio of upstream to downstream packets.
        }
        :param windowed_traces: a segment of TCP traces, ASSUMED TO BE SORTED BY
            TIME in ascending order.
        :param client_ips: the IP addresses/subnets of the suspected PT clients.
        :param feature_selection: chooses sets of features to check for and
            include in the output. If None, include all features. Options:
            USE_ENTROPY       : Entropy features
            USE_INTERVAL      : Mean interval
            USE_INTERVAL_BINS : Binned intervals
            USE_TCP_LEN       : Top and mean TCP lengths
            USE_TCP_LEN_BINS  : Binned TCP lengths
            USE_PSH           : Ratio of PSH packets in ACK packets
        :returns: three-tuple: a dictionary containing the stats as described
            above, a set of remote IP addresses seen in the window, and a list of
            client ips seen in this window.
    """

    client_subnets = [data.utils.build_subnet(i) for i in client_ips]
    client_ips_seen = set([])

    all_features = True if (feature_selection is None) or (len(feature_selection) == 0) else False
    entropy_on = True if all_features else constants.USE_ENTROPY in feature_selection
    interval_on = True if all_features else constants.USE_INTERVAL in feature_selection
    interval_bins_on = True if all_features else constants.USE_INTERVAL_BINS in feature_selection
    tcp_len_on = True if all_features else constants.USE_TCP_LEN in feature_selection
    tcp_len_bins_on = True if all_features else constants.USE_TCP_LEN_BINS in feature_selection
    psh_on = True if all_features else constants.USE_PSH in feature_selection

    if not client_subnets:
        return {}, set([]), [] # client_ip does not match the traces.

    stats = {}
    interval_ranges = [1000, 10000, 100000, 1000000]
    tcp_len_ranges = [100, 200, 500, 1000]
    # TCP length segmented into low/empty payload, moderate payloads, and
    # high/close-to-MTU payload. Most systems have a default MTU at nearly 1500
    # bytes.

    ips = set([])

    seqs_seen_up = set([])
    entropies_up = []
    intervals_up = []
    intervals_up_bins = {i: 0 for i in interval_ranges}
    payload_lengths_up = []
    payload_lengths_up_bins = {i: 0 for i in tcp_len_ranges}
    psh_up = 0
    ack_up = 0
    traces_up = list(filter(lambda x: any([i.overlaps(data.utils.build_subnet(x['src'])) for i in client_subnets]), windowed_traces))

    seqs_seen_down = set([])
    entropies_down = []
    intervals_down = []
    intervals_down_bins = {i: 0 for i in interval_ranges}
    payload_lengths_down = []
    payload_lengths_down_bins = {i: 0 for i in tcp_len_ranges}
    psh_down = 0
    ack_down = 0
    traces_down = list(filter(lambda x: any([i.overlaps(data.utils.build_subnet(x['dst'])) for i in client_subnets]), windowed_traces))

    if len(traces_up) > 0 and len(traces_down) > 0:
        stats['up_down_ratio'] = float(len(traces_up)) / len(traces_down)
    else:
        stats['up_down_ratio'] = 0

    # Now tally upstream frames.
    if len(traces_up) > 1:
        prev_time = None
        for trace in traces_up:

            # Ignore non-TCP packets.
            if trace['tcp_info'] == None:
                continue
            ips.add(trace['dst'])
            client_ips_seen.add(trace['src'])

            # Entropy tally.
            if entropy_on:
                trace_tcp = trace['tcp_info']
                entropies_up.append(entropy.EntropyAnalyser.byte_entropy(trace_tcp['payload']))

            # Interval information.
            if trace_tcp['seq'] not in seqs_seen_up:
                seqs_seen_up.add(trace_tcp['seq'])

                if prev_time is None:
                    prev_time = float(trace['time']) * 1000000
                else:
                    interval = abs(float(trace['time']) * 1000000 - prev_time) # Just in case not sorted, even though that would be incorrect.
                    intervals_up.append(interval)
                    # If the interval is above 1 second, ignore its bin membership.
                    for k in interval_ranges:
                        if interval < k:
                            intervals_up_bins[k] += 1
                    prev_time = float(trace['time']) * 1000000

            # Payload length tally.
            if tcp_len_on:
                payload_lengths_up.append(len(trace_tcp['payload']))
            if tcp_len_bins_on:
                for k in tcp_len_ranges:
                    if len(trace_tcp['payload']) < k:
                        payload_lengths_up_bins[k] += 1

            # ACK/PSH information.
            if psh_on:
                if trace_tcp['flags']['ACK'] == True:
                    ack_up += 1
                    if trace_tcp['flags']['PSH'] == True:
                        psh_up += 1

        if entropy_on:
            stats['mean_entropy_up'] = np.mean(entropies_up)
            stats['max_entropy_up'] = np.max(entropies_up)
            stats['min_entropy_up'] = np.min(entropies_up)

        if interval_on:
            if len(intervals_up) == 0: # Cap at 1 second.
                stats['mean_interval_up'] = 1000000
            else:
                stats['mean_interval_up'] = np.mean(intervals_up)
        if interval_bins_on:
            intervals_up_bins = sorted(intervals_up_bins.items(), key=itemgetter(0))
            for interval_bin in intervals_up_bins:
                stats['bin_' + str(interval_bin[0]) + '_interval_up'] = interval_bin[1]

        if tcp_len_on:
            up_counts = Counter(payload_lengths_up).items()
            up_counts_sorted = sorted(up_counts, key=itemgetter(1))
            stats['top1_tcp_len_up'] = up_counts_sorted[0][0] if len(up_counts_sorted) > 0 else 0
            stats['top2_tcp_len_up'] = up_counts_sorted[1][0] if len(up_counts_sorted) > 1 else 0
            stats['mean_tcp_len_up'] = np.mean(payload_lengths_up)
        if tcp_len_bins_on:
            payload_lengths_up_bins = sorted(payload_lengths_up_bins.items(), key=itemgetter(0))
            for length_bin in payload_lengths_up_bins:
                stats['bin_' + str(length_bin[0]) + '_interval_up'] = length_bin[1]

        if psh_on:
            if ack_up > 0:
                stats['push_ratio_up'] = float(psh_up) / ack_up
            else:
                stats['push_ratio_up'] = 0

    else: # Default to zeros if insufficient frames to check.

        if entropy_on:
            stats['mean_entropy_up'] = 0
            stats['max_entropy_up'] = 0
            stats['min_entropy_up'] = 0

        if interval_on:
            stats['mean_interval_up'] = 1000000
        if interval_bins_on:
            for interval_bin in intervals_up_bins:
                stats['bin_' + str(interval_bin) + '_interval_up'] = 0

        if tcp_len_on:
            stats['top1_tcp_len_up'] = 0
            stats['top2_tcp_len_up'] = 0
            stats['mean_tcp_len_up'] = 0
        if tcp_len_bins_on:
            for length_bin in payload_lengths_up_bins:
                stats['bin_' + str(length_bin) + '_interval_up'] = 0

        if psh_on:
            stats['push_ratio_up'] = 0

    # Now tally downstream frames.
    if len(traces_down) > 0:
        prev_time = None
        for trace in traces_down:

            # Ignore non-TCP packets.
            if trace['tcp_info'] == None:
                continue
            ips.add(trace['src'])
            client_ips_seen.add(trace['dst'])

            # Entropy tally.
            if entropy_on:
                trace_tcp = trace['tcp_info']
                entropies_down.append(entropy.EntropyAnalyser.byte_entropy(trace_tcp['payload']))

            # Interval information.
            if trace_tcp['seq'] not in seqs_seen_down:
                seqs_seen_down.add(trace_tcp['seq'])

                if prev_time is None:
                    prev_time = float(trace['time']) * 1000000
                else:
                    interval = abs(float(trace['time']) * 1000000 - prev_time)
                    intervals_down.append(interval)
                    # If the interval is above 1 second, ignore its bin membership.
                    for k in interval_ranges:
                        if interval < k:
                            intervals_down_bins[k] += 1
                    prev_time = float(trace['time']) * 1000000


            # Payload length tally.
            if tcp_len_on:
                payload_lengths_down.append(len(trace_tcp['payload']))
            if tcp_len_bins_on:
                for k in tcp_len_ranges:
                    if len(trace_tcp['payload']) < k:
                        payload_lengths_down_bins[k] += 1

            # ACK/PSH information.
            if psh_on:
                if trace_tcp['flags']['ACK'] == True:
                    ack_down += 1
                    if trace_tcp['flags']['PSH'] == True:
                        psh_down += 1

        if entropy_on:
            stats['mean_entropy_down'] = np.mean(entropies_down)
            stats['max_entropy_down'] = np.max(entropies_down)
            stats['min_entropy_down'] = np.min(entropies_down)

        if interval_on:
            if len(intervals_down) == 0: # Cap at 1 second.
                stats['mean_interval_down'] = 1000000
            else:
                stats['mean_interval_down'] = np.mean(intervals_down)
        if interval_bins_on:
            intervals_down_bins = sorted(intervals_down_bins.items(), key=itemgetter(0))
            for interval_bin in intervals_down_bins:
                stats['bin_' + str(interval_bin[0]) + '_interval_down'] = interval_bin[1]

        if tcp_len_on:
            down_counts = Counter(payload_lengths_down).items()
            down_counts_sorted = sorted(down_counts, key=itemgetter(1))
            stats['top1_tcp_len_down'] = down_counts_sorted[0][0] if len(down_counts_sorted) > 0 else 0
            stats['top2_tcp_len_down'] = down_counts_sorted[1][0] if len(down_counts_sorted) > 1 else 0
            stats['mean_tcp_len_down'] = np.mean(payload_lengths_down)
        if tcp_len_bins_on:
            payload_lengths_down_bins = sorted(payload_lengths_down_bins.items(), key=itemgetter(0))
            for length_bin in payload_lengths_down_bins:
                stats['bin_' + str(length_bin[0]) + '_interval_down'] = length_bin[1]

        if psh_on:
            if ack_down > 0:
                stats['push_ratio_down'] = float(psh_down) / ack_down
            else:
                stats['push_ratio_down'] = 0

    else:
        # Default to least optimistic if insufficient frames to check.
        if entropy_on:
            stats['mean_entropy_down'] = 0
            stats['max_entropy_down'] = 0
            stats['min_entropy_down'] = 0

        if interval_on:
            stats['mean_interval_down'] = 1000000
        if interval_bins_on:
            for interval_bin in intervals_down_bins:
                stats['bin_' + str(interval_bin) + '_interval_down'] = 0

        if tcp_len_on:
            stats['top1_tcp_len_down'] = 0
            stats['top2_tcp_len_down'] = 0
            stats['mean_tcp_len_down'] = 0
        if tcp_len_bins_on:
            for length_bin in payload_lengths_down_bins:
                stats['bin_' + str(length_bin) + '_interval_down'] = 0

        if psh_on:
            stats['push_ratio_down'] = 0


    return stats, ips, client_ips_seen


def synchronise_traces(traces, target_time, sort=False):
    """
    Synhronise the input traces by shifting the time of the first frame to align
    with the target time provided.
    :param traces: input traces to be time shifted, should be chronologically
        ordered or set sort to True, otherwise results will be unexpected.
    :param target_time: a float value that is a valid UNIX timestamp to 6 d.p.
    :param sort: if True, the function will chronologically sort the input traces
        first.
    :returns: time shifted input traces.
    """

    if not isinstance(target_time, float):
        raise ValueError("Invalid target time.")

    if len(traces) == 0:
        return []

    if sort:
        traces = sorted(traces, key=itemgetter('time'))

    traces_start_time = float(traces[0]['time'])
    diff = target_time - traces_start_time

    for trace in traces:
        trace['time'] = float(trace['time']) + diff

    return traces
