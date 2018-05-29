from .. import analytics, data
from .strategy import DetectionStrategy

import os
from sys import exit, argv
from datetime import date, datetime
from operator import itemgetter
from math import log1p, floor
import numpy as np


class EntropyEstimationStrategy(DetectionStrategy):
    """
    Detecting high-entropy fully-encrypted based on estimation of
    sliding window entropy on TCP payloads in both directions.
    """


    NAME = "Entropy Estimation Strategy"
    DESCRIPTION = "Detecting high-entropy PTs based on sliding window entropy estimation."
    _DEBUG_PREFIX = "EntropyEst"
    RUN_CONFIG_DESCRIPTION = ["Window Size", "Test Size", "Percentile Threshold"]
    
    MIN_TEST_SIZES = [1024, 512, 256, 128]
    WINDOW_SIZE = 64 # Default.
    WINDOW_SIZES = [32, 64, 96]
    THRESHOLDS = [0.1, 0.5, 1, 5] # %ile threshold for high-entropy proportions
    FALSE_POSITIVE_SCORE_WEIGHT = 0.5
    TLS_HTTP_INCLUSION_THRESHOLD = 0.1


    def __init__(self, pt_pcap, negative_pcap=None, debug=True):
        super().__init__(pt_pcap, negative_pcap, debug=debug)
        self._analyser = analytics.entropy.EntropyAnalyser()

        # Store intermediate results and cut-off thresholds.
        self._strategic_states['TPR'] = {}
        self._strategic_states['FPR'] = {}
        self._strategic_states['blocked_ips'] = {}
        self._strategic_states['cut_off'] = {}

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


    def interpret_config(self, config_set):
        """
        Block size, p-value threshold, and criteria distinguish entropy distribution tests.
        """

        if config_set is not None:
            return "Entropy estimation test with byte block size {} and max tested payload size {}, subject to {} pct threshold. .".format(config_set[0], config_set[1], config_set[2])
        else:
            return ""


    def config_specific_penalisation(self, config_set):
        """
        Byte block sizes and min test sizes for entropy uniformity and distribution
        tests will have already inversely proportionally affected the positive 
        execution time. As the percentile threshold has no effect on the difficulty
        of strategy deployment, no strategy-specific penalisation is required.
        """

        return 0


    def test_validation_split(self, split_ratio):
        """
        Not needed, as a fixed strategy is used.
        """

        return ([], [])


    def positive_run(self, **kwargs):
        """
        Results from these tests estimate the presence of fully encrypted payloads
        by counting the number of sliding windows with large numbers of unique bytes.

        :param int window_size: the size of blocks of payload bytes tested in KS and
            AD. Default is set in :const:`BLOCK_SIZE`.
        :param int test_size: the minimum number of bytes tested in each payload for
            testing, with default set in :const:`TEST_SIZES`.
        :param int threshold: the percentile threshold for the proportion of high
            entropy packets considered as positives.
        """

        window_size = self.WINDOW_SIZE if 'window_size' not in kwargs else kwargs['window_size']
        test_size = min(self.MIN_TEST_SIZES) if 'test_size' not in kwargs else kwargs['test_size']
        threshold = max(self.THRESHOLDS) if 'threshold' not in kwargs else kwargs['threshold']
        config = (window_size, test_size, threshold)
        mtu_threshold = analytics.constants.MTU_FRAME_AVOIDANCE_THRESHOLD
        
        examined_packets = 0
        detected = []
        self._strategic_states['cut_off'][config] = 0
        for t in self._pt_packets:
            payload = t['tcp_info']['payload'][:mtu_threshold]
            if len(payload) >= max(self._protocol_min_length, window_size, test_size):
                examined_packets += 1
                detected.append(self._analyser.entropy_estimation(payload, window_size))
        if examined_packets == 0:
            self.debug_print("Warning: no packets examined, TCP payload length threshold or input filters may be incorrect.")
            return 0

        self._strategic_states['cut_off'][config] = floor(np.percentile(detected, threshold))

        # Store result in the state space and register it.
        self._strategic_states['TPR'][config] = float(100 - threshold) / 100 # Fixed positive thresholding.
        self.register_performance_stats(config, TPR=self._strategic_states['TPR'][config])

        return self._strategic_states['TPR'][config]


    def negative_run(self, **kwargs):
        """
        Test an identical configuration on negative packets. Reporting falsely blocked IPs.

        :param int window_size: the size of blocks of payload bytes tested in KS and
            AD. Default is set in :const:`BLOCK_SIZE`.
        :param int test_size: the minimum number of bytes tested in each payload for
            testing, with default set in :const:`TEST_SIZES`.
        :param int threshold: the percentile threshold for the proportion of high
            entropy packets considered as positives.
        """

        window_size = self.WINDOW_SIZE if 'window_size' not in kwargs else kwargs['window_size']
        test_size = min(self.MIN_TEST_SIZES) if 'test_size' not in kwargs else kwargs['test_size']
        threshold = max(self.THRESHOLDS) if 'threshold' not in kwargs else kwargs['threshold']
        config = (window_size, test_size, threshold)
        mtu_threshold = analytics.constants.MTU_FRAME_AVOIDANCE_THRESHOLD

        false_positives = 0
        blocked_ips = set([])
        for t in self._neg_packets:
            payload = t['tcp_info']['payload'][:mtu_threshold]

            if len(payload) >= max(self._protocol_min_length, window_size, test_size):
                high_entropy_proportion = self._analyser.entropy_estimation(payload, window_size)
                if high_entropy_proportion >= self._strategic_states['cut_off'][config]:
                    blocked_ips.add(t['dst'])
                    false_positives += 1

        self._negative_blocked_ips = blocked_ips


        # Unlike the positive case, we consider the false positive rate to be
        # over all packets, rather than just the ones were are interested in.
        # Store all results in the state space.
        self._strategic_states['FPR'][config] = false_positives / self._neg_collection_total
        self._strategic_states['blocked_ips'][config] = blocked_ips
        self._false_positive_blocked_rate = float(len(blocked_ips)) / self._negative_unique_ips

        # Register the results.
        self.register_performance_stats(config, FPR=self._strategic_states['FPR'][config],
         ip_block_rate=self._false_positive_blocked_rate)

        return self._strategic_states['FPR'][config]


    def report_blocked_ips(self):
        """
        Return a Wireshark-compatible filter expression to allow viewing blocked
        packets in Wireshark. Useful for studying false positives.

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
        PT input filters should be given as :const:`data.constants.IP_SRC` and :const:`data.constants.IP_DST`,
        and changed around if testing for downstream rather than upstream direction.
        Negative input filters specifying innocent clients should be given as an :const:`data.constants.IP_SRC`.

        :param int protocol_min_length: Optionally set the minimum handshake TCP
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
        for packet in self._pt_packets:
            if packet["tls_info"] is not None:
                pt_tls_count += 1
            elif packet["http_info"] is not None:
                pt_http_count += 1

        if float(pt_tls_count) / len(self._pt_packets) >= self.TLS_HTTP_INCLUSION_THRESHOLD:
            self.debug_print("Considering TLS packets based on PT trace observations only.")
            self._pt_packets = [i for i in self._pt_packets if i["tls_info"] is not None]
            self._neg_packets = [i for i in self._neg_packets if i["tls_info"] is not None]
        else:
            self.debug_print("Disregarding TLS packets based on PT trace observations.")
            self._pt_packets = [i for i in self._pt_packets if i["tls_info"] is None]
            self._neg_packets = [i for i in self._neg_packets if i["tls_info"] is None]
            self._disregard_tls = True

        if float(pt_http_count) / len(self._pt_packets) >= self.TLS_HTTP_INCLUSION_THRESHOLD:
            self.debug_print("Considering HTTP packets based on PT trace observations only.")
            self._pt_packets = [i for i in self._pt_packets if i["http_info"] is not None]
            self._neg_packets = [i for i in self._neg_packets if i["http_info"] is not None]
        else:
            self.debug_print("Disregarding HTTP packets based on PT trace observations.")
            self._pt_packets = [i for i in self._pt_packets if i["http_info"] is None]
            self._neg_packets = [i for i in self._neg_packets if i["http_info"] is None]
            self._disregard_http = True

        self.debug_print("- Running iterations of detection strategy on positive and negative test packets...")

        for s in self.MIN_TEST_SIZES:
            for b in self.WINDOW_SIZES:
                for c in self.THRESHOLDS:

                    self.debug_print("- Calculating positive cut-off at {} pct, for min {} bytes, {} byte windows on positive packets...".format(c, s, b))
                    tp = self.run_on_positive((b, s, c), window_size=b, test_size=s, threshold=c)

                    self.debug_print("- Testing min {} bytes, {} byte windows on negative packets...".format(s, b))
                    fp = self.run_on_negative((b, s, c), window_size=b, test_size=s, threshold=c)
                    self.debug_print("min {} bytes, {} byte windows at {} pct cut-off gives false positive rate {}.".format(s, b, c, fp))

        # Find the best true positive and false positive performance.
        tps = self._strategic_states['TPR']
        fps = self._strategic_states['FPR']
        best_true_positives = [i[0] for i in sorted(tps.items(), key=itemgetter(1), reverse=True)] # True positive in descending order.
        best_false_positives = [i[0] for i in sorted(fps.items(), key=itemgetter(1))] # False positive in ascending order.
        best_true_positive = best_true_positives[0]
        best_false_positive = best_false_positives[0]

        # Score the configurations based on their difference from the best one.
        # As it is guaranteed for the difference to be between 0 and 1,
        # log1p(100) - log1p(diff*100) is used to create a descending score
        # exponentially rewarding low difference values.
        configs = list(tps.keys())
        true_positives_scores = [(log1p(100) - log1p(abs(tps[best_true_positive] - tps[i])*100)) for i in configs]
        false_positives_scores = [(log1p(100) - log1p(abs(tps[best_false_positive] - fps[i])*100)) for i in configs]
        average_scores = [(true_positives_scores[i] * (1-self.FALSE_POSITIVE_SCORE_WEIGHT) + false_positives_scores[i] * self.FALSE_POSITIVE_SCORE_WEIGHT) for i in range(len(true_positives_scores))]
        best_config = configs[average_scores.index(max(average_scores))]

        self._true_positive_rate = tps[best_config]
        self._false_positive_rate = fps[best_config]
        self._negative_blocked_ips = self._strategic_states["blocked_ips"]
        self.debug_print("Best classification performance:")
        self.debug_print("block size: {}, min test size: {}, positive cutoff threshold: {} pct.".format(best_config[0], best_config[1], best_config[2]))
        self.debug_print("True positive rate: {}; False positive rate: {}".format(self._true_positive_rate, self._false_positive_rate))

        self._negative_blocked_ips = self._strategic_states['blocked_ips'][best_config]
        self._false_positive_blocked_rate = float(len(self._negative_blocked_ips)) / self._negative_unique_ips
        self.debug_print("This classification configuration blocked {:0.2f}% of IPs seen.".format(self._false_positive_blocked_rate*100))

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    pt_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', argv[2])
    detector = EntropyEstimationStrategy(pt_path, unobfuscated_path, debug=True)
    detector.setup(pt_ip_filters=[(argv[3], data.constants.IP_SRC),
     (argv[4], data.constants.IP_DST)], negative_ip_filters=[(argv[5],
     data.constants.IP_SRC)], pt_collection=argv[6], negative_collection=argv[7])
    detector.run(protocol_min_length=int(argv[8]))

    print(detector.report_blocked_ips())
    score, best_config = detector._score_performance_stats()
    print("Score: {}, best config: {}.".format(score, detector.interpret_config(best_config)))
    print(detector.make_csv())
