import analytics, data
from strategy.strategy import DetectionStrategy

import os
from datetime import date, datetime

class Obfs4Strategy(DetectionStrategy):
    """
    Detecting Obfs4 based on payload byte-uniformity and entropy-distribution,
    as a reproduction of Wang et al. Should only be applied to client-to-server
    traces.
    """

    # TODO: exclude SSH (hard) and HTTP traffic as obfs4 traffic do not have
    # signatures.

    NAME = "Obfs4 Detection Strategy"
    DESCRIPTION = "Detecting Obfs4 based on payload byte-uniformity and entropy-distribution."
    _MONGO_KEY = "Obfs4" # Alphanumeric key for MongoDB.

    OBFS4_MIN_LENGTH = 149
    BLOCK_SIZE = 8
    DEBUG = True

    def __init__(self, pt_pcap, negative_pcap=None):
        super().__init__(pt_pcap, negative_pcap, self.DEBUG)


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
         "tcp_info.payload": {"$ne": b''}, "tls_info": {"$eq": None}}


    def test_validation_split(self, split_ratio):
        """
        Not needed, as a fixed strategy is used.
        """

        return ([], [])


    def positive_run(self):
        """
        Three different criteria of combing results from KS byte-uniformity, Entropy
        Distribution, and Anderson_Darling tests together, all using p=0.1 as
        the hypothesis rejection threshold, with the latter two using a byte
        block size of 8. Reporting a selected criterion.
        """

        analyser = analytics.entropy.EntropyAnalyser()

        # Three criteria possible: [conservative, majority voting, and sensitive].
        # Corresponding to [all, majority, any] when deciding whether to flag
        # a packet as obfs4.

        criteria = ['conservative', 'majority', 'sensitive']
        identified = {i: 0 for i in criteria}
        reporting = 'majority'
        examined_traces = 0

        for t in self._pt_traces:
            payload = t['tcp_info']['payload']

            if len(payload) > self.OBFS4_MIN_LENGTH:
                examined_traces += 1
                p1 = analyser.kolmogorov_smirnov_uniform_test(payload[:2048])
                p2 = analyser.kolmogorov_smirnov_dist_test(payload[:2048], self.BLOCK_SIZE)
                p3 = analyser.anderson_darling_dist_test(payload[:2048], self.BLOCK_SIZE)
                agreement = len(list(filter(lambda x: x >= 0.1, [p1, p2, p3['min_threshold']])))

                if agreement == 3:
                    identified['conservative'] += 1

                if agreement >= 2:
                    identified['majority'] += 1

                if agreement > 0:
                    identified['sensitive'] += 1

        return float(identified[reporting]) / examined_traces


    def negative_run(self):
        """
        Test the same thing on negative traces. Reporting blocked IPs.
        """

        analyser = analytics.entropy.EntropyAnalyser()
        criteria = ['conservative', 'majority', 'sensitive']
        identified = {i: 0 for i in criteria}
        blocked_ips = {i: set([]) for i in criteria}
        reporting = 'majority'

        for t in self._neg_traces:
            payload = t['tcp_info']['payload']

            if len(payload) > self.OBFS4_MIN_LENGTH:
                p1 = analyser.kolmogorov_smirnov_uniform_test(payload[:2048])
                p2 = analyser.kolmogorov_smirnov_dist_test(payload[:2048], self.BLOCK_SIZE)
                p3 = analyser.anderson_darling_dist_test(payload[:2048], self.BLOCK_SIZE)
                agreement = len(list(filter(lambda x: x >= 0.1, [p1, p2, p3['min_threshold']])))

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
    obfs4_path = os.path.join(parent_path, 'examples', 'local', 'obfs4long.pcap')
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'unobfuscated_acstest.pcap')
    detector = Obfs4Strategy(obfs4_path, unobfuscated_path)
    detector.run(pt_ip_filters=[('10.248.100.93', data.constants.IP_SRC),
        ('37.218.245.14', data.constants.IP_DST)],
        negative_ip_filters=[('128.232.17.20', data.constants.IP_SRC)])

    detector.clean_up_mongo()
    print(detector.report_blocked_ips())
