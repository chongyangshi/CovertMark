import analytics, data
from strategy.strategy import DetectionStrategy

import os
from sys import exit, argv
from datetime import date, datetime
from operator import itemgetter
from math import log1p


class EntropyStrategy(DetectionStrategy):
    """
    Detecting high-entropy encryption based on payload byte-uniformity and
    entropy-distribution tests on TCP payloads in both directions.
    """


    NAME = "Entropy Detection Strategy"
    DESCRIPTION = "Detecting high-entropy PTs based on payload byte-uniformity and entropy-distribution."
    _MONGO_KEY = "Entropy" # Alphanumeric key for MongoDB.
    _DEBUG_PREFIX = _MONGO_KEY

    BLOCK_SIZE = 8
    DEBUG = True

    # Three criteria possible: [conservative, majority voting, and sensitive].
    # Corresponding to [all, majority, any] when deciding whether to flag
    # a packet as likely high-entropy encrypted PT traffic.
    CRITERIA = ['conservative', 'majority', 'sensitive']
    P_THRESHOLDS = [0.05, 0.1, 0.15, 0.2]
    BLOCK_SIZES = [4, 8, 16, 32, 64]
    CANDIDATES = 3
    FALSE_POSITIVE_SCORE_WEIGHT = 0.5
    TLS_HTTP_INCLUSION_THRESHOLD = 0.1


    def __init__(self, pt_pcap, negative_pcap=None):
        super().__init__(pt_pcap, negative_pcap, debug=self.DEBUG)
        self._analyser = analytics.entropy.EntropyAnalyser()

        # To store results from different block sizes and p-value thresholds, as
        # well as different criteria, rates are indexed with a three-tuple
        # (block_size, p_threshold, criterion).
        self._strategic_states['accuracy_true'] = {}
        self._strategic_states['accuracy_false'] = {}
        self._strategic_states['blocked_ips'] = {}

        # Record disregards.
        self._disregard_tls = False
        self._disregard_http = False


    def set_strategic_filter(self):
        """
        The base strategy is to only observe TCP packets that do not have valid
        TLS records (as identified by dpkt) but do bear a non-blank payload.
        """

        # TCP payload required here, with whether to include or disregard HTTP
        # and TLS packets are done by run when observing retrieved packet
        # patterns.

        self._strategic_packet_filter = {"tcp_info": {"$ne": None},
         "tcp_info.payload": {"$ne": b''}}


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

        block_size = self.BLOCK_SIZE if 'block_size' not in kwargs else kwargs['block_size']
        p_threshold = 0.1 if not kwargs['p_threshold'] else kwargs['p_threshold']

        identified = {i: 0 for i in self.CRITERIA}
        reporting = 'majority'
        examined_traces = 0

        for t in self._pt_traces:
            payload = t['tcp_info']['payload']

            if len(payload) >= self._protocol_min_length:
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

        block_size = self.BLOCK_SIZE if 'block_size' not in kwargs else kwargs['block_size']
        p_threshold = 0.1 if not kwargs['p_threshold'] else kwargs['p_threshold']

        identified = {i: 0 for i in self.CRITERIA}
        blocked_ips = {i: set([]) for i in self.CRITERIA}
        reporting = 'majority'

        for t in self._neg_traces:
            payload = t['tcp_info']['payload']

            if len(payload) >= self._protocol_min_length:
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

        wireshark_output = ""
        if not self._disregard_tls:
            wireshark_output += "ssl && "
        else:
            wireshark_output += "!ssl && "

        if not self._disregard_http:
            wireshark_output += "http && "
        else:
            wireshark_output += "!http && "

        wireshark_output += "tcp_len >= " + str(self._protocol_min_length) + " && "

        wireshark_output += "("
        for i, ip in enumerate(list(self._negative_blocked_ips)):
            wireshark_output += "ip.dst_host == \"" + ip + "\" "
            if i < len(self._negative_blocked_ips) - 1:
                wireshark_output += "|| "
        wireshark_output += ")"

        return wireshark_output


    def run_strategy(self, **kwargs):
        """
        PT input filters should be given in IP_SRC and IP_DST, and changed around
        if testing for downstream rather than upstream direction.
        Negative input filters specifying innocent clients should be given as IP_SRC.
        :param protocol_min_length: Optionally set the minimum handshake TCP
            payload length of packets in that direction, allowing disregard of
            short packets.
        """

        protocol_min_length = 0 if 'protocol_min_length' not in kwargs else kwargs['protocol_min_length']
        if not isinstance(protocol_min_length, int) or protocol_min_length < 0:
            self.debug_print("Assuming minimum protocol TCP payload length as 0.")
            self._protocol_min_length = 0
        else:
            self._protocol_min_length = protocol_min_length

        # Check whether we should include or disregard TLS or HTTP packets.
        pt_tls_count = 0
        pt_http_count = 0
        for trace in self._pt_traces:
            if trace["tls_info"] is not None:
                pt_tls_count += 1
            elif trace["http_info"] is not None:
                pt_http_count += 1

        if float(pt_tls_count) / len(self._pt_traces) >= self.TLS_HTTP_INCLUSION_THRESHOLD:
            self.debug_print("Considering TLS packets based on PT trace observations.")
        else:
            self.debug_print("Disregarding TLS packets based on PT trace observations.")
            self._pt_traces = [i for i in self._pt_traces if i["tls_info"] is None]
            self._neg_traces = [i for i in self._neg_traces if i["tls_info"] is None]
            self._disregard_tls = True

        if float(pt_http_count) / len(self._pt_traces) >= self.TLS_HTTP_INCLUSION_THRESHOLD:
            self.debug_print("Considering HTTP packets based on PT trace observations.")
        else:
            self.debug_print("Disregarding HTTP packets based on PT trace observations.")
            self._pt_traces = [i for i in self._pt_traces if i["http_info"] is None]
            self._neg_traces = [i for i in self._neg_traces if i["http_info"] is None]
            self._disregard_http = True

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

    pt_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', argv[2])
    detector = EntropyStrategy(pt_path, unobfuscated_path)
    detector.setup(pt_ip_filters=[(argv[3], data.constants.IP_SRC),
     (argv[4], data.constants.IP_DST)], negative_ip_filters=[(argv[5],
     data.constants.IP_SRC)], pt_collection=argv[6], negative_collection=argv[7])
    detector.run(protocol_min_length=int(argv[8]))

    print(detector.report_blocked_ips())
