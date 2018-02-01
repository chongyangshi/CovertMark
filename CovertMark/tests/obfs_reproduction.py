from data import parser, mongo, constants
from analytics import entropy

import os, sys
from base64 import b64decode

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
long_path = os.path.join(parent_path, 'examples', 'local')
analyser = entropy.EntropyAnalyser()
positive_negative = ['obfs4long', 'unobfuscatedlong']
OBFS4_MIN = 149

for test in positive_negative:
    #example_path = os.path.join(parent_path, 'examples', test + '.pcap')
    example_path = os.path.join(long_path, test + '.pcap')
    print("Loading traces from {}...".format(example_path))
    a = parser.PCAPParser(example_path)

    if test == positive_negative[0]:
        a.set_ip_filter([('10.248.100.93', constants.IP_SRC), ('37.218.245.14', constants.IP_DST)])
    else:
        a.set_ip_filter([('172.28.195.198', constants.IP_SRC)])

    name = a.load_and_insert_new("Test collection.")

    if not name:
        continue

    print()
    total = m.count_traces(name, {})
    print("In total {} client->server traces on {}.".format(total, test))
    all_dst_ips = m.distinct_traces(name, 'dst')

    if test == positive_negative[0]:
        traces = m.find_traces(name, {"tcp_info": {"$ne": None}, "tcp_info.payload": {"$ne": b''}})
    else:
        traces = m.find_traces(name, {"tcp_info": {"$ne": None}, "tcp_info.payload": {"$ne": b''}})

    qualifying = len(traces)
    print("In total {} client->server test-qualifying traces on {}.".format(qualifying, test))
    #
    # non_uniform = 0
    # uniform = 0
    # entropy_non_uniform = 0
    # entropy_uniform = 0
    all_uniform = 0
    either_uniform = 0
    conservative_blocked_ips = set([])
    elaborate_blocked_ips = set([])

    for t in traces:
        if t['tcp_info'] is None:
            continue

        if t['tls_info'] is not None:
            # An interesting observation that a majority of identified false
            # positive traces in the unobfuscated set have TLS records, while
            # obfs4 traces do not. This forms a simple and effective criteria but
            # also trivial to circumvent with obfs4 injecting pseudo TLS records.
            continue

        payload = b64decode(t['tcp_info']['payload'])
        if len(payload) > OBFS4_MIN:
            p1 = analyser.kolmogorov_smirnov_uniform_test(payload[:2048])
            p2 = analyser.kolmogorov_smirnov_dist_test(payload[:2048], 8)
            p3 = analyser.anderson_darling_dist_test(payload[:2048], 8)
            agreement = len(list(filter(lambda x: x >= 0.1, [p1, p2, p3['min_threshold']])))

            if agreement == 3:
                all_uniform += 1
                conservative_blocked_ips.add(t['dst'])

            if agreement > 0:
                either_uniform += 1
                elaborate_blocked_ips.add(t['dst'])

    # print()
    # print("Byte Non-uniform: {}; uniform: {}.".format(non_uniform, uniform))
    # print("Entropy Non-uniform: {}; uniform: {}.".format(entropy_non_uniform, entropy_uniform))
    # print()

    if test == positive_negative[1]:
        print("Conservatively blocking (both uniform) FALSE positive:")
        print("{} out of {} ({:0.2f}%) all traces blocked".format(all_uniform, total, 100*float(all_uniform)/total))
        print("{} IPs blocked out of {} ({:0.2f}%)".format(len(conservative_blocked_ips), all_dst_ips, 100*len(conservative_blocked_ips)/float(all_dst_ips)))
    else:
        print("Conservatively blocking (both uniform) TRUE positive:")
        print("The single IP of bridge is identified by {} out of {} ({:0.2f}%) length-qualifying client-server traces.".format(all_uniform, qualifying, 100*float(all_uniform)/qualifying))
    print()

    if test == positive_negative[1]:
        print("Elaborate blocking (either uniform) FALSE positive:")
        print("{} out of {} ({:0.2f}%) all traces blocked".format(either_uniform, total, 100*float(either_uniform)/total))
        print("{} IPs blocked out of {} ({:0.2f}%)".format(len(elaborate_blocked_ips), all_dst_ips, 100*len(elaborate_blocked_ips)/float(all_dst_ips)))
    else:
        print("Elaborate blocking (either uniform) TRUE positive:")
        print("The single IP of bridge is identified by {} out of {} ({:0.2f}%) length-qualifying client-server traces.".format(either_uniform, qualifying, 100*float(either_uniform)/qualifying))
    print()

    wireshark_output = "Elaborately blocked Wireshark: tcp.payload && "
    for i, ip in enumerate(list(elaborate_blocked_ips)):
        wireshark_output += "ip.dst_host == \"" + ip + "\" "
        if i < len(elaborate_blocked_ips) - 1:
            wireshark_output += "|| "
    print(wireshark_output)

    wireshark_output = "Conservatively blocked Wireshark: tcp.payload && "
    for i, ip in enumerate(list(conservative_blocked_ips)):
        wireshark_output += "ip.dst_host == \"" + ip + "\" "
        if i < len(conservative_blocked_ips) - 1:
            wireshark_output += "|| "
    print(wireshark_output)

    m.delete_collection(name)
