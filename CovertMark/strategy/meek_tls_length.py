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
    MINIMUM_TPR = 0.40
    # While this method does not require high TPR, a minimum threshold needs to
    # be maintained to ensure fitness.


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

        # Round performance to four decimal places.
        tps = self._strategic_states['TPR']
        fps = self._strategic_states['FPR']

        # Find the best true positive and false positive performance.
        # Descending order of TPR, then ascending by bandwidth and cluster size to maximise efficiency.
        best_true_positives = [i[0] for i in sorted(tps.items(), key=lambda x: (x[1], -x[0][0], -x[0][1]), reverse=True)]
        # False positive in ascending order, then by bandwidth and cluster size ascending.
        best_false_positives = [i[0] for i in sorted(fps.items(), key=lambda x: (x[1], x[0][0], x[0][1]))]

        # Walk down the list of lowest false positives to find the first config
        # satisfying the minimum true positive rate requirement.
        best_config = None
        for config in best_false_positives:
            if tps[config] >= self.MINIMUM_TPR:
                best_config = config
                break

        # If none satisfies the minimum true positive rate requirement, report
        # as failure.
        if best_config is None:
            self.debug_print("No bandwidth and cluster size achieved the minimum true positive rate required ({}), giving up.".format(self.MINIMUM_TPR))
            return (None, None)

        self._true_positive_rate = tps[best_config]
        self._false_positive_rate = fps[best_config]
        if best_config[1] == 1:
            self._strategic_states['top_cluster'] = self._strategic_states['top_cluster'][best_config[0]]
        else:
            self._strategic_states['top_cluster'] = self._strategic_states['top_two_clusters'][best_config[0]]

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
    # meek_path = os.path.join(parent_path, 'examples', 'meek.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'unobfuscated.pcap')
    # detector = MeekLengthStrategy(meek_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('172.28.192.46', data.constants.IP_SRC),
    #     ('13.33.51.7', data.constants.IP_DST)],
    #     negative_ip_filters=[('172.28.192.204', data.constants.IP_SRC)],
    #     pt_collection="traces20180217a1a60caecdc1ce9931db55b6696c86338b3a9b3e",
    #     negative_collection="traces2018021750d58c2a2eaced13d138ebe723360a0fa59ad348")

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
    #     negative_ip_filters=[('128.232.17.0/24', data.constants.IP_SRC)],
    #     pt_collection="traces20180217bedd6553b1ad347c547c6440db8625a30124958b",
    #     negative_collection="traces201802179204e6b362c82a2e90f71e261570f36a69ff064e")

    # detector.clean_up_mongo()

    pt_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', argv[2])
    detector = MeekLengthStrategy(pt_path, unobfuscated_path)
    detector.run(pt_ip_filters=[(argv[3], data.constants.IP_EITHER)],
     negative_ip_filters=[(argv[4], data.constants.IP_EITHER)],
     pt_collection=argv[5], negative_collection=argv[6])

    print(detector.report_blocked_ips())
