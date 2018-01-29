from data import parser, mongo, constants
from analytics import entropy

import os, sys
from base64 import b64decode

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
analyser = entropy.EntropyAnalyser()
positive_negative = ['obfs4', 'unobfuscated']

for test in positive_negative:
    example_path = os.path.join(parent_path, 'examples', test + '.pcap')
    a = parser.PCAPParser(example_path)

    if test == positive_negative[0]:
        a.set_ip_filter([('172.28.192.204', constants.IP_SRC), ('37.218.245.14', constants.IP_DST)])
    else:
        a.set_ip_filter([('172.28.192.204', constants.IP_SRC)])

    name = a.load_and_insert_new("Test collection.")

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

    non_uniform = 0
    uniform = 0
    entropy_non_uniform = 0
    entropy_uniform = 0
    both_uniform = 0
    either_uniform = 0
    conservative_blocked_ips = set([])
    elaborate_blocked_ips = set([])

    for t in traces:
        if t['tcp_info'] is None:
            continue

        payload = b64decode(t['tcp_info']['payload'])
        if len(payload) > 149:
            p1 = analyser.kolmogorov_smirnov_uniform_test(payload[:2048])
            if p1 < 0.1:
                non_uniform += 1
            else:
                uniform += 1
            p2 = analyser.kolmogorov_smirnov_dist_test(payload[:2048], 8)
            if p2 < 0.1:
                entropy_non_uniform += 1
            else:
                entropy_uniform += 1

            if p1 > 0.1 and p2 > 0.1:
                both_uniform += 1
                conservative_blocked_ips.add(t['dst'])

            if p1 > 0.1 or p2 > 0.1:
                either_uniform += 1
                elaborate_blocked_ips.add(t['dst'])

    print()
    print("Byte Non-uniform: {}; uniform: {}.".format(non_uniform, uniform))
    print("Entropy Non-uniform: {}; uniform: {}.".format(entropy_non_uniform, entropy_uniform))
    print()

    if test == 'unobfuscated':
        print("Conservatively blocking (both uniform) FALSE positive:")
        print("{} out of {} ({:0.2f}%) all traces blocked".format(both_uniform, total, 100*float(both_uniform)/total))
        print("{} IPs blocked out of {} ({:0.2f}%)".format(len(conservative_blocked_ips), all_dst_ips, 100*len(conservative_blocked_ips)/float(all_dst_ips)))
    else:
        print("Conservatively blocking (both uniform) TRUE positive:")
        print("The single IP of bridge is identified by {} out of {} ({:0.2f}%) length-qualifying client-server traces.".format(both_uniform, qualifying, 100*float(both_uniform)/qualifying))
    print()

    if test == 'unobfuscated':
        print("Elaborate blocking (both uniform) FALSE positive:")
        print("{} out of {} ({:0.2f}%) all traces blocked".format(either_uniform, total, 100*float(either_uniform)/total))
        print("{} IPs blocked out of {} ({:0.2f}%)".format(len(elaborate_blocked_ips), all_dst_ips, 100*len(elaborate_blocked_ips)/float(all_dst_ips)))
    else:
        print("Elaborate blocking (both uniform) TRUE positive:")
        print("The single IP of bridge is identified by {} out of {} ({:0.2f}%) length-qualifying client-server traces.".format(either_uniform, qualifying, 100*float(either_uniform)/qualifying))
    print()

    m.delete_collection(name)
