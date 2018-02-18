import analytics, data
from strategy.strategy import DetectionStrategy

import os
from sys import exit, argv
from datetime import date, datetime
from operator import itemgetter
from math import log1p

class Obfs4Strategy(DetectionStrategy):
    """
    Detecting Obfs4 based on payload byte-uniformity and entropy-distribution,
    as a reproduction of Wang et al. Should only be applied to client-to-server
    traces.
    """


    NAME = "Obfs4 Detection Strategy"
    DESCRIPTION = "Detecting Obfs4 based on payload byte-uniformity and entropy-distribution."
    _MONGO_KEY = "Obfs4" # Alphanumeric key for MongoDB.

    OBFS4_MIN_LENGTH = 149
    BLOCK_SIZE = 8
    DEBUG = True

    # Three criteria possible: [conservative, majority voting, and sensitive].
    # Corresponding to [all, majority, any] when deciding whether to flag
    # a packet as obfs4.
    CRITERIA = ['conservative', 'majority', 'sensitive']
    P_THRESHOLDS = [0.05, 0.1, 0.15, 0.2]
    BLOCK_SIZES = [4, 8, 16, 32, 64]
    CANDIDATES = 3
    FALSE_POSITIVE_SCORE_WEIGHT = 0.5


    def __init__(self, pt_pcap, negative_pcap=None):
        super().__init__(pt_pcap, negative_pcap, self.DEBUG)
        self._analyser = analytics.entropy.EntropyAnalyser()

        # To store results from different block sizes and p-value thresholds, as
        # well as different criteria, rates are indexed with a three-tuple
        # (block_size, p_threshold, criterion).
        self._strategic_states['accuracy_true'] = {}
        self._strategic_states['accuracy_false'] = {}
        self._strategic_states['blocked_ips'] = {}


    def set_strategic_filter(self):
        """
        The base strategy is to only observe TCP packets that do not have valid
        TLS records (as identified by dpkt) but do bear a non-blank payload.
        """

        # An interesting observation that a majority of identified false
        # positive traces in the unobfuscated set have TLS records, while
        # obfs4 traces do not. This forms a simple and effective criteria but
        # also trivial to circumvent with obfs4 injecting pseudo TLS records.

        self._strategic_packet_filter = {"tcp_info": {"$ne": None},
         "tcp_info.payload": {"$ne": b''}, "tls_info": {"$eq": None},
         "http_info": {"$eq": None}}


    def test_validation_split(self, split_ratio):
        """
        Not needed, as a fixed strategy is used.
        """

        return ([], [])


    def positive_run(self, **kwargs):
        """
        Three different criteria of combing results from KS byte-uniformity, Entropy
        Distribution, and Anderson_Darling tests together, all using p=0.1 as
        the hypothesis rejection threshold, with the latter two using a byte
        block size of 8. Reporting a selected criterion.
        :param block_size: the size of blocks of payload bytes tested in KS and
            AD. Default set in self.BLOCK_SIZE.
        :param p_threshold: the p-value threshold at which uniform random
            hypothesis can be rejected, defaulted at 0.1.
        """

        block_size = self.BLOCK_SIZE if not kwargs['block_size'] else kwargs['block_size']
        p_threshold = 0.1 if not kwargs['p_threshold'] else kwargs['p_threshold']

        identified = {i: 0 for i in self.CRITERIA}
        reporting = 'majority'
        examined_traces = 0

        for t in self._pt_traces:
            payload = t['tcp_info']['payload']

            if len(payload) > self.OBFS4_MIN_LENGTH:
                examined_traces += 1
                p1 = self._analyser.kolmogorov_smirnov_uniform_test(payload[:2048])
                p2 = self._analyser.kolmogorov_smirnov_dist_test(payload[:2048], block_size)
                p3 = self._analyser.anderson_darling_dist_test(payload[:2048], block_size)
                agreement = len(list(filter(lambda x: x >= p_threshold, [p1, p2, p3['min_threshold']])))

                if agreement == 3:
                    identified['conservative'] += 1

                if agreement >= 2:
                    identified['majority'] += 1

                if agreement > 0:
                    identified['sensitive'] += 1

        # Store all results in the state space.
        for i in identified:
            self._strategic_states['accuracy_true'][(block_size, p_threshold, i)] = float(identified[i]) / examined_traces

        return float(identified[reporting]) / examined_traces


    def negative_run(self, **kwargs):
        """
        Test the same thing on negative traces. Reporting blocked IPs.
        :param block_size: the size of blocks of payload bytes tested in KS and
            AD. Default set in self.BLOCK_SIZE.
        :param p_threshold: the p-value threshold at which uniform random
            hypothesis can be rejected, defaulted at 0.1.
        """

        block_size = self.BLOCK_SIZE if not kwargs['block_size'] else kwargs['block_size']
        p_threshold = 0.1 if not kwargs['p_threshold'] else kwargs['p_threshold']

        identified = {i: 0 for i in self.CRITERIA}
        blocked_ips = {i: set([]) for i in self.CRITERIA}
        reporting = 'majority'

        for t in self._neg_traces:
            payload = t['tcp_info']['payload']

            if len(payload) > self.OBFS4_MIN_LENGTH:
                p1 = self._analyser.kolmogorov_smirnov_uniform_test(payload[:2048])
                p2 = self._analyser.kolmogorov_smirnov_dist_test(payload[:2048], block_size)
                p3 = self._analyser.anderson_darling_dist_test(payload[:2048], block_size)
                agreement = len(list(filter(lambda x: x >= p_threshold, [p1, p2, p3['min_threshold']])))

                if agreement == 3:
                    blocked_ips['conservative'].add(t['dst'])
                    identified['conservative'] += 1

                if agreement >= 2:
                    blocked_ips['majority'].add(t['dst'])
                    identified['majority'] += 1

                if agreement > 0:
                    blocked_ips['sensitive'].add(t['dst'])
                    identified['sensitive'] += 1

        self._negative_blocked_ips = blocked_ips[reporting]

        # Unlike the positive case, we consider the false positive rate to be
        # over all traces, rather than just the ones were are interested in.
        # Store all results in the state space.
        for i in identified:
            self._strategic_states['accuracy_false'][(block_size, p_threshold, i)] = float(identified[i]) / self._neg_collection_total
            self._strategic_states['blocked_ips'][(block_size, p_threshold, i)] = blocked_ips[i]

        return float(identified[reporting]) / self._neg_collection_total


    def report_blocked_ips(self):
        """
        Return a Wireshark-compatible filter expression to allow viewing blocked
        traces in Wireshark. Useful for studying false positives.
        :returns: a Wireshark-compatible filter expression string.
        """

        wireshark_output = "!ssl && tcp.len > 149 && ("
        for i, ip in enumerate(list(self._negative_blocked_ips)):
            wireshark_output += "ip.dst_host == \"" + ip + "\" "
            if i < len(self._negative_blocked_ips) - 1:
                wireshark_output += "|| "
        wireshark_output += ")"

        return wireshark_output


    def run(self, pt_ip_filters=[], negative_ip_filters=[], pt_split=False,
     pt_split_ratio=0.7, pt_collection=None, negative_collection=None):
        """
        Overriding default run() to test over multiple block sizes and p-value
        thresholds.
        """

        self._run(pt_ip_filters, negative_ip_filters,
         pt_collection=pt_collection, negative_collection=negative_collection)
        self.debug_print("- Running iterations of detection strategy on positive and negative test traces...")

        for p in self.P_THRESHOLDS:
            for b in self.BLOCK_SIZES:

                self.debug_print("- Testing p={}, {} byte block on positive traces...".format(p, b))
                tp = self._run_on_positive(block_size=b, p_threshold=p)
                self.debug_print("p={}, {} byte block gives true positive rate {}.".format(p, b, tp))

                self.debug_print("- Testing p={}, {} byte block on negative traces...".format(p, b))
                fp = self._run_on_negative(block_size=b, p_threshold=p)
                self.debug_print("p={}, {} byte block gives false positive rate {}.".format(p, b, fp))

        # Find the best true positive and false positive performance.
        tps = self._strategic_states['accuracy_true']
        fps = self._strategic_states['accuracy_false']
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
        self.debug_print("block size: {}, p-value threshold: {}, agreement criteria: {}.".format(best_config[0], best_config[1], best_config[2]))
        self.debug_print("True positive rate: {}; False positive rate: {}".format(self._true_positive_rate, self._false_positive_rate))

        self._negative_blocked_ips = self._strategic_states['blocked_ips'][best_config]
        self._false_positive_blocked_rate = float(len(self._negative_blocked_ips)) / self._negative_unique_ips
        self.debug_print("This classification configuration blocked {:0.2f}% of IPs seen.".format(self._false_positive_blocked_rate))

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # Shorter example.
    # obfs4_path = os.path.join(parent_path, 'examples', 'obfs4.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'unobfuscated.pcap')
    # detector = Obfs4Strategy(obfs4_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('172.28.192.204', data.constants.IP_SRC),
    #     ('37.218.245.14', data.constants.IP_DST)],
    #     negative_ip_filters=[('172.28.192.204', data.constants.IP_SRC)])

    # Longer local example.
    # obfs4_path = os.path.join(parent_path, 'examples', 'local', 'obfs4long.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'unobfuscatedlongext.pcap')
    # detector = Obfs4Strategy(obfs4_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('10.248.100.93', data.constants.IP_SRC),
    #     ('37.218.245.14', data.constants.IP_DST)],
    #     negative_ip_filters=[('172.28.195.198', data.constants.IP_SRC),
    #     ('172.28.194.2', data.constants.IP_SRC),
    #     ('172.28.193.192', data.constants.IP_SRC)])

    # Longer ACS Test.
    # obfs4_path = os.path.join(parent_path, 'examples', 'local', 'obfs4long.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'unobfuscated_acstest.pcap')
    # detector = Obfs4Strategy(obfs4_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('10.248.100.93', data.constants.IP_SRC),
    #     ('37.218.245.14', data.constants.IP_DST)],
    #     negative_ip_filters=[('128.232.17.20', data.constants.IP_SRC)])

    pt_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', argv[2])
    detector = Obfs4Strategy(pt_path, unobfuscated_path)
    detector.run(pt_ip_filters=[(argv[3], data.constants.IP_EITHER)],
     negative_ip_filters=[(argv[4], data.constants.IP_EITHER)],
     pt_collection=argv[5], negative_collection=argv[6])

    print(detector.report_blocked_ips())
