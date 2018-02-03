import analytics, data
from strategy.strategy import DetectionStrategy

import os
from datetime import date, datetime

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

    def __init__(self, pt_pcap, negative_pcap=None):
        super().__init__(pt_pcap, negative_pcap, self.DEBUG)


    def set_strategic_filter(self):
        """
        All meek packets are valid TLS packets by design, therefore TCP packets
        without valid TLS records can be discarded from consideration. This is
        of course after the input filtering from client-to-server only.
        """

        self._strategic_packet_filter = {"tls_info": {"$ne": None}}


    def test_validation_split(self, split_ratio):
        """
        Not currently needed, as a fixed strategy is used.
        """

        return ([], [])


    def positive_run(self):
        """
        Because this simple strategy is based on common global TCP payload lengths,
        the identified trace ratio is not very useful here. Currently the
        MeanShift bandwidth/max difference is set to 1.
        """

        most_frequent = analytics.traffic.ordered_tcp_payload_length_frequency(self._pt_traces, True, 1)
        top_cluster = most_frequent[0]
        top_cluster_identified = 0
        for trace in self._pt_traces:
            if len(trace['tcp_info']['payload']) in top_cluster:
                top_cluster_identified += 1

        # Pass the cluster to the negative run.
        self._strategic_states['top_cluster'] = top_cluster

        self.debug_print("Because this simple strategy is based on common global TCP payload lengths, the identified trace ratio is not very useful here.")
        return top_cluster_identified / len(self._pt_traces)


    def negative_run(self):
        """
        Now we check the identified lengths against negative traces. Because
        TLS packets with a TCP payload as small as meek's are actually very
        rare, this simple strategy becomes effective.
        """

        top_cluster = self._strategic_states['top_cluster']
        falsely_identified = 0
        for trace in self._neg_traces:
            if len(trace['tcp_info']['payload']) in top_cluster:
                falsely_identified += 1
                self._negative_blocked_ips.add(trace['dst'])

        # Unlike the positive case, we consider the false positive rate to be
        # over all traces, rather than just the ones were are interested in.
        return float(falsely_identified) / self._neg_collection_total


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
        wireshark_output += ")"

        return wireshark_output


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # Shorter example.
    # meek_path = os.path.join(parent_path, 'examples', 'meek.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'unobfuscated.pcap')
    # detector = MeekLengthStrategy(meek_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('172.28.192.46', data.constants.IP_SRC),
    #     ('13.33.51.7', data.constants.IP_DST)],
    #     negative_ip_filters=[('172.28.192.204', data.constants.IP_SRC)])

    # Longer local example.
    meek_path = os.path.join(parent_path, 'examples', 'local', 'meeklong.pcap')
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'unobfuscatedlong.pcap')
    detector = MeekLengthStrategy(meek_path, unobfuscated_path)
    detector.run(pt_ip_filters=[('192.168.0.42', data.constants.IP_SRC),
        ('13.32.68.163', data.constants.IP_DST)],
        negative_ip_filters=[('172.28.195.198', data.constants.IP_SRC)])

    detector.clean_up_mongo()
    print(detector.report_blocked_ips())
