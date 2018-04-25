from .. import analytics, data
from .strategy import DetectionStrategy

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


    NAME = "Entropy Distribution Strategy"
    DESCRIPTION = "Detecting high-entropy PTs based on payload byte-uniformity and entropy-distribution."
    _DEBUG_PREFIX = "Entropy"
    RUN_CONFIG_DESCRIPTION = ["Block Size", "Test Size", "Criterion"]

    # Three criteria possible: [majority voting, and sensitive].
    # Corresponding to [majority, any] when deciding whether to flag
    # a packet as likely high-entropy encrypted PT traffic.
    CRITERIA = [2, 1]
    CRITERIA_DESCRIPTIONS = {2: "majority voting", 1: "sensitive"}
    MAX_CRITERION = 3
    P_THRESHOLD = 0.1
    TEST_SIZES = [256, 512, 1024, 1536]
    BLOCK_SIZE = 8 # Default.
    BLOCK_SIZES = [8, 16, 32, 64]
    FALSE_POSITIVE_SCORE_WEIGHT = 0.5
    TLS_HTTP_INCLUSION_THRESHOLD = 0.1


    def __init__(self, pt_pcap, negative_pcap=None, debug=True):
        super().__init__(pt_pcap, negative_pcap, debug=debug)
        self._analyser = analytics.entropy.EntropyAnalyser()

        # To store results from different block sizes and test sizes, as
        # well as different criteria, rates are indexed with a three-tuple
        # (block_size, test_size, criterion).
        self._strategic_states['TPR'] = {}
        self._strategic_states['FPR'] = {}
        self._strategic_states['blocked_ips'] = {}

        # Record disregards.
        self._disregard_tls = False
        self._disregard_http = False

        # Caching to not repeat entropy distribution tests between different criteria.
        self._agreements_cache_positive = {}
        self._agreements_cache_negative = {}
        self._blocked_cache_negative = {}


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
            return "Entropy distribution test with byte block size {} and max tested payload size {}, subject to {} test voting criterion.".format(config_set[0], config_set[1], self.CRITERIA_DESCRIPTIONS[config_set[2]])
        else:
            return ""


    def config_specific_penalisation(self, config_set):
        """
        Byte block sizes and max test sizes for entropy uniformity and distribution
        tests will have already inversely proportionally affected the positive 
        execution time. Therefore the only additional penalty is based on the number of
        statistical run needed as determined by the number of agreements required,
        with 10% penalty for each additional statistical tests beyond the minimum.
        """

        if config_set not in self._strategic_states['TPR'].keys():
            return 0
        else:
            return 0.1 * max(0, (config_set[2] - min(self.CRITERIA)))

        return 0


    def test_validation_split(self, split_ratio):
        """
        Not needed, as a fixed strategy is used.
        """

        return ([], [])


    def positive_run(self, **kwargs):
        """
        Three different criteria of combining results from KS byte-uniformity and
        Entropy Distribution, and Anderson_Darling tests together, with variable max
        tested payload sizes and test block sizes. Results from these tests detect 
        uniformly high entropy payloads that are likely results of pseudo-random
        encryptions.

        :param int block_size: the size of blocks of payload bytes tested in KS and
            AD. Default is set in :const:`BLOCK_SIZE`.
        :param int test_size: the maximum number of bytes tested in each payload,
            with default set in :const:`TEST_SIZES`.
        :param int criterion: the number of rejected hypothesis among all tests
            needed to reach a positive conclusion.
        """

        block_size = self.BLOCK_SIZE if 'block_size' not in kwargs else kwargs['block_size']
        test_size = max(self.TEST_SIZES) if 'test_size' not in kwargs else kwargs['test_size']
        criterion = self.MAX_CRITERION if 'criterion' not in kwargs else kwargs['criterion']

       
        config = (block_size, test_size, criterion)
        subconfig = (block_size, test_size)

        if subconfig in self._agreements_cache_positive:
            agreements = self._agreements_cache_positive[subconfig]
        else:
            agreements = []
            examined_traces = 0
            for t in self._pt_traces:
                payload = t['tcp_info']['payload']

                if len(payload) >= max(self._protocol_min_length, block_size):
                    examined_traces += 1
                    p1 = self._analyser.kolmogorov_smirnov_uniform_test(payload[:test_size])
                    p2 = self._analyser.kolmogorov_smirnov_dist_test(payload[:test_size], block_size)
                    p3 = self._analyser.anderson_darling_dist_test(payload[:test_size], block_size)
                    agreement = len(list(filter(lambda x: x >= self.P_THRESHOLD, [p1, p2, p3['min_threshold']])))
                    agreements.append(agreement)

            if examined_traces == 0:
                self.debug_print("Warning: no traces examined, TCP payload length threshold or input filters may be incorrect.")
                return 0
            
            self._agreements_cache_positive[subconfig] = agreements
            
        # Calculate the number of positive identifications under the criterion.
        identified = sum([1 if i >= criterion else 0 for i in agreements]) 

        # Store result in the state space and register it.
        self._strategic_states['TPR'][config] = float(identified) / len(agreements)
        self.register_performance_stats(config, TPR=self._strategic_states['TPR'][config])

        return self._strategic_states['TPR'][config]


    def negative_run(self, **kwargs):
        """
        Test an identical configuration on negative traces. Reporting falsely blocked IPs.

        :param int block_size: the size of blocks of payload bytes tested in KS and
            AD. Default is set in :const:`BLOCK_SIZE`.
        :param int test_size: the maximum number of bytes tested in each payload,
            with default set in :const:`TEST_SIZES`.
        :param int criterion: the number of rejected hypothesis among all tests
            needed to reach a positive conclusion.
        """

        block_size = self.BLOCK_SIZE if 'block_size' not in kwargs else kwargs['block_size']
        test_size = max(self.TEST_SIZES) if 'test_size' not in kwargs else kwargs['test_size']
        criterion = self.MAX_CRITERION if 'criterion' not in kwargs else kwargs['criterion']
        config = (block_size, test_size, criterion)
        subconfig = (block_size, test_size)

        if subconfig in self._agreements_cache_negative:
            agreements = self._agreements_cache_negative[subconfig]
            blocked_ips = self._blocked_cache_negative[subconfig]
            # Overwrite positive execution time with that of the positive run originally calculating.
            self.register_performance_stats(config, time=self._time_statistics[config]['time'])
        else:
            agreements = []
            blocked_ips = set([])
            for t in self._neg_traces:
                payload = t['tcp_info']['payload']

                if len(payload) >= max(self._protocol_min_length, block_size):
                    p1 = self._analyser.kolmogorov_smirnov_uniform_test(payload[:test_size])
                    p2 = self._analyser.kolmogorov_smirnov_dist_test(payload[:test_size], block_size)
                    p3 = self._analyser.anderson_darling_dist_test(payload[:test_size], block_size)
                    agreement = len(list(filter(lambda x: x >= self.P_THRESHOLD, [p1, p2, p3['min_threshold']])))
                    agreements.append(agreement)

                    if agreement >= criterion:
                        blocked_ips.add(t['dst'])
            
            self._agreements_cache_negative[subconfig] = agreements
            self._blocked_cache_negative[subconfig] = blocked_ips

        self._negative_blocked_ips = blocked_ips

        # Calculate the number of positive identifications under the criterion.
        identified = sum([1 if i >= criterion else 0 for i in agreements])

        # Unlike the positive case, we consider the false positive rate to be
        # over all traces, rather than just the ones were are interested in.
        # Store all results in the state space.
        self._strategic_states['FPR'][config] = float(identified) / self._neg_collection_total
        self._strategic_states['blocked_ips'][config] = blocked_ips
        self._false_positive_blocked_rate = float(len(blocked_ips)) / self._negative_unique_ips

        # Register the results.
        self.register_performance_stats(config, FPR=self._strategic_states['FPR'][config],
         ip_block_rate=self._false_positive_blocked_rate)

        return self._strategic_states['FPR'][config]


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
        for trace in self._pt_traces:
            if trace["tls_info"] is not None:
                pt_tls_count += 1
            elif trace["http_info"] is not None:
                pt_http_count += 1

        if float(pt_tls_count) / len(self._pt_traces) >= self.TLS_HTTP_INCLUSION_THRESHOLD:
            self.debug_print("Considering TLS packets based on PT trace observations only.")
            self._pt_traces = [i for i in self._pt_traces if i["tls_info"] is not None]
            self._neg_traces = [i for i in self._neg_traces if i["tls_info"] is not None]
        else:
            self.debug_print("Disregarding TLS packets based on PT trace observations.")
            self._pt_traces = [i for i in self._pt_traces if i["tls_info"] is None]
            self._neg_traces = [i for i in self._neg_traces if i["tls_info"] is None]
            self._disregard_tls = True

        if float(pt_http_count) / len(self._pt_traces) >= self.TLS_HTTP_INCLUSION_THRESHOLD:
            self.debug_print("Considering HTTP packets based on PT trace observations only.")
            self._pt_traces = [i for i in self._pt_traces if i["http_info"] is not None]
            self._neg_traces = [i for i in self._neg_traces if i["http_info"] is not None]
        else:
            self.debug_print("Disregarding HTTP packets based on PT trace observations.")
            self._pt_traces = [i for i in self._pt_traces if i["http_info"] is None]
            self._neg_traces = [i for i in self._neg_traces if i["http_info"] is None]
            self._disregard_http = True

        self.debug_print("- Running iterations of detection strategy on positive and negative test traces...")

        for s in self.TEST_SIZES:
            for b in self.BLOCK_SIZES:
                for c in self.CRITERIA:
                    self.debug_print("Using {} criterion, requiring {}/{} statistical tests to reject hypothesis.".format(\
                     self.CRITERIA_DESCRIPTIONS[c], c, self.MAX_CRITERION))

                    self.debug_print("- Testing max {} bytes, {} byte block on positive traces...".format(s, b))
                    tp = self.run_on_positive((b, s, c), block_size=b, test_size=s, criterion=c)
                    self.debug_print("max {} bytes, {} byte block gives true positive rate {}.".format(s, b, tp))

                    self.debug_print("- Testing max {} bytes, {} byte block on negative traces...".format(s, b))
                    fp = self.run_on_negative((b, s, c), block_size=b, test_size=s, criterion=c)
                    self.debug_print("max {} bytes, {} byte block gives false positive rate {}.".format(s, b, fp))

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
        self.debug_print("block size: {}, max test size: {}, agreement criteria: {}.".format(best_config[0], best_config[1], self.CRITERIA_DESCRIPTIONS[best_config[2]]))
        self.debug_print("True positive rate: {}; False positive rate: {}".format(self._true_positive_rate, self._false_positive_rate))

        self._negative_blocked_ips = self._strategic_states['blocked_ips'][best_config]
        self._false_positive_blocked_rate = float(len(self._negative_blocked_ips)) / self._negative_unique_ips
        self.debug_print("This classification configuration blocked {:0.2f}% of IPs seen.".format(self._false_positive_blocked_rate*100))

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    pt_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', argv[2])
    detector = EntropyStrategy(pt_path, unobfuscated_path, debug=True)
    detector.setup(pt_ip_filters=[(argv[3], data.constants.IP_SRC),
     (argv[4], data.constants.IP_DST)], negative_ip_filters=[(argv[5],
     data.constants.IP_SRC)], pt_collection=argv[6], negative_collection=argv[7])
    detector.run(protocol_min_length=int(argv[8]))

    print(detector.report_blocked_ips())
    score, best_config = detector._score_performance_stats()
    print("Score: {}, best config: {}.".format(score, detector.interpret_config(best_config)))
    print(detector.make_csv())
