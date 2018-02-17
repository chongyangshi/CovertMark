import analytics, data
from strategy.strategy import DetectionStrategy

import os
from datetime import date, datetime
from operator import itemgetter
from math import log1p

class MeekLengthStrategy(DetectionStrategy):
    """
    Detecting meek through clustering the payload length of TLS-loaded TCP packets
    client-to-server, taking advantage of its frequent client pings with a very
    small payload and is not greatly varying in length. Should only be applied
    to client-to-server traces.
    """

    NAME = "Meek Length Detection Strategy"
    DESCRIPTION = "Detecting meek based on TLS-loaded TCP packet lengths."
    _MONGO_KEY = "MeekL" # Alphanumeric key for MongoDB.

    DEBUG = True
    MEANSHIFT_BWS = [1, 2, 3, 5, 10]
    FALSE_POSITIVE_SCORE_WEIGHT = 0.9

    def __init__(self, pt_pcap, negative_pcap=None):
        super().__init__(pt_pcap, negative_pcap, self.DEBUG)
        self._strategic_states['TPR'] = {}
        self._strategic_states['FPR'] = {}
        self._strategic_states['top_cluster'] = {}
        self._strategic_states['top_two_clusters'] = {}
        self._strategic_states['blocked'] = {}


    def set_strategic_filter(self):
        """
        All meek packets are valid TLS packets by design, therefore TCP packets
        without valid TLS records can be discarded from consideration. This is
        of course after the input filtering making traces client-to-server only.
        """

        self._strategic_packet_filter = {"tls_info": {"$ne": None}}


    def test_validation_split(self, split_ratio):
        """
        Not currently needed, as a fixed strategy is used.
        """

        return ([], [])


    def positive_run(self, **kwargs):
        """
        Because this simple strategy is based on common global TCP payload lengths,
        the identified trace ratio is not very useful here.
        :param bandwidth: the bandwidth used for meanshift clustering payload lengths.
        """

        bandwidth = 1 if not kwargs['bandwidth'] else kwargs['bandwidth']

        most_frequent = analytics.traffic.ordered_tcp_payload_length_frequency(self._pt_traces, True, bandwidth)
        top_cluster = most_frequent[0]
        top_two_clusters = top_cluster.union(most_frequent[1])
        top_cluster_identified = 0
        top_two_clusters_identified = 0
        for trace in self._pt_traces:
            if len(trace['tcp_info']['payload']) in top_cluster:
                top_cluster_identified += 1
                if len(trace['tcp_info']['payload']) in top_two_clusters:
                    top_two_clusters_identified += 1

        # Pass the cluster to the negative run.
        self._strategic_states['top_cluster'][bandwidth] = top_cluster
        self._strategic_states['top_two_clusters'][bandwidth] = top_two_clusters

        self._strategic_states['TPR'][(bandwidth, 1)] = top_cluster_identified / len(self._pt_traces)
        self._strategic_states['TPR'][(bandwidth, 2)] = top_two_clusters_identified / len(self._pt_traces)

        return self._strategic_states['TPR'][(bandwidth, 1)]


    def negative_run(self, **kwargs):
        """
        Now we check the identified lengths against negative traces. Because
        TLS packets with a TCP payload as small as meek's are actually very
        rare, this simple strategy becomes effective.
        :param bandwidth: the bandwidth used for meanshift clustering payload lengths.
        """

        bandwidth = 1 if not kwargs['bandwidth'] else kwargs['bandwidth']

        top_cluster = self._strategic_states['top_cluster'][bandwidth]
        top_falsely_identified = 0
        self._strategic_states['blocked'][(bandwidth, 1)] = set([])
        for trace in self._neg_traces:
            if len(trace['tcp_info']['payload']) in top_cluster:
                top_falsely_identified += 1
                self._strategic_states['blocked'][(bandwidth, 1)].add(trace['dst'])

        top_two_clusters = self._strategic_states['top_two_clusters'][bandwidth]
        top_two_falsely_identified = 0
        self._strategic_states['blocked'][(bandwidth, 2)] = set([])
        for trace in self._neg_traces:
            if len(trace['tcp_info']['payload']) in top_two_clusters:
                top_two_falsely_identified += 1
                self._strategic_states['blocked'][(bandwidth, 2)].add(trace['dst'])

        # Unlike the positive case, we consider the false positive rate to be
        # over all traces, rather than just the ones were are interested in.
        self._strategic_states['FPR'][(bandwidth, 1)] = float(top_falsely_identified) / self._neg_collection_total
        self._strategic_states['FPR'][(bandwidth, 2)] = float(top_two_falsely_identified) / self._neg_collection_total

        return self._strategic_states['FPR'][(bandwidth, 1)]


    def report_blocked_ips(self):
        """
        Return a Wireshark-compatible filter expression to allow viewing blocked
        traces in Wireshark. Useful for studying false positives.
        :returns: a Wireshark-compatible filter expression string.
        """

        wireshark_output = "ssl && tcp.payload && ("
        for i, ip in enumerate(list(self._negative_blocked_ips)):
            wireshark_output += "ip.dst_host == \"" + ip + "\" "
            if i < len(self._negative_blocked_ips) - 1:
                wireshark_output += "|| "
        wireshark_output += ") && ("
        for i, l in enumerate(list(self._strategic_states['top_cluster'])):
            wireshark_output += "tcp.len == " + str(l)
            if i < len(self._strategic_states['top_cluster']) - 1:
                wireshark_output += " || "
        wireshark_output += ")"

        return wireshark_output


    def run(self, pt_ip_filters=[], negative_ip_filters=[], pt_split=False,
     pt_split_ratio=0.7, pt_collection=None, negative_collection=None):
        """
        Overriding default run() to test with multiple bandwidths.
        """

        self._run(pt_ip_filters, negative_ip_filters,
         pt_collection=pt_collection, negative_collection=negative_collection)

        self.debug_print("- Testing the following bandwidths for MeanShift: {}".format(', '.join([str(i) for i in self.MEANSHIFT_BWS])))
        for bw in self.MEANSHIFT_BWS:

            self.debug_print("- Running MeanShift on positives with bandwidth {}...".format(bw))
            tp = self._run_on_positive(bandwidth=bw)
            self.debug_print("True positive rate on bandwidth {} for top cluster: {}".format(bw, tp))

            self.debug_print("- Checking MeanShift on negatives with bandwidth {}...".format(bw))
            fp = self._run_on_negative(bandwidth=bw)
            self.debug_print("False positive rate on bandwidth {} for top cluster: {}".format(bw, fp))

        # Find the best true positive and false positive performance.
        tps = self._strategic_states['TPR']
        fps = self._strategic_states['FPR']
        best_true_positives = [i[0] for i in sorted(tps.items(), key=itemgetter(1), reverse=True)] # True positive in descending order.
        best_false_positives = [i[0] for i in sorted(fps.items(), key=itemgetter(1))] # False positive in ascending order.
        best_true_positive = best_true_positives[0]
        best_false_positive = best_false_positives[0]

        # Score the configurations based on their difference from the best one.
        # As it is guaranteed for the difference to be between 0 and 1,
        # log1p(100) - loge(diff*100) is used to create a descending score
        # exponentially rewarding low difference values.
        configs = list(tps.keys())
        true_positives_scores = [(log1p(100) - log1p(abs(tps[best_true_positive] - tps[i])*100)) for i in configs]
        false_positives_scores = [(log1p(100) - log1p(abs(tps[best_false_positive] - fps[i])*100)) for i in configs]
        average_scores = [(true_positives_scores[i] * (1-self.FALSE_POSITIVE_SCORE_WEIGHT) + false_positives_scores[i] * self.FALSE_POSITIVE_SCORE_WEIGHT) for i in range(len(true_positives_scores))]
        best_config = configs[average_scores.index(max(average_scores))]

        self._true_positive_rate = tps[best_config]
        self._false_positive_rate = fps[best_config]
        self.debug_print("Best classification performance:")
        self.debug_print("Bandwidth: {}, using top {} cluster(s).".format(best_config[0], best_config[1]))
        self.debug_print("True positive rate: {}; False positive rate: {}".format(self._true_positive_rate, self._false_positive_rate))

        self._negative_blocked_ips = self._strategic_states['blocked'][best_config]
        self._false_positive_blocked_rate = float(len(self._negative_blocked_ips)) / self._negative_unique_ips
        self.debug_print("This classification configuration blocked {:0.2f}% of IPs seen.".format(self._false_positive_blocked_rate))

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # Shorter example.
    meek_path = os.path.join(parent_path, 'examples', 'meek.pcap')
    unobfuscated_path = os.path.join(parent_path, 'examples', 'unobfuscated.pcap')
    detector = MeekLengthStrategy(meek_path, unobfuscated_path)
    detector.run(pt_ip_filters=[('172.28.192.46', data.constants.IP_SRC),
        ('13.33.51.7', data.constants.IP_DST)],
        negative_ip_filters=[('172.28.192.204', data.constants.IP_SRC)])

    # Longer local example.
    # meek_path = os.path.join(parent_path, 'examples', 'local', 'meeklong.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'unobfuscatedlongext.pcap')
    # detector = MeekLengthStrategy(meek_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('192.168.0.42', data.constants.IP_SRC),
    #     ('13.32.68.163', data.constants.IP_DST)],
    #     negative_ip_filters=[('172.28.195.198', data.constants.IP_SRC),
    #     ('172.28.194.2', data.constants.IP_SRC),
    #     ('172.28.193.192', data.constants.IP_SRC)])

    # Longer ACS example.
    # meek_path = os.path.join(parent_path, 'examples', 'local', 'meeklonger.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'cantab.pcap')
    # detector = MeekLengthStrategy(meek_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('10.248.98.196', data.constants.IP_SRC),
    #     ('54.192.2.159', data.constants.IP_DST)],
    #     negative_ip_filters=[('128.232.17.0/24', data.constants.IP_SRC)])

    # detector.clean_up_mongo()
    print(detector.report_blocked_ips())
