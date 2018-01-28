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
        a.set_ip_filter([('37.218.245.14', constants.IP_DST)])
    else:
        a.set_ip_filter([('172.28.192.204', constants.IP_SRC)])

    name = a.load_and_insert_new("Test collection.")

    print("In total {} client->server traces on {}.".format(m.count_traces(name, {}), test))

    if test == positive_negative[0]:
        traces = m.find_traces(name, {"tcp_info": {"$ne": None}, "tcp_info.payload": {"$ne": b''}})
    else:
        traces = m.find_traces(name, {"tcp_info": {"$ne": None}, "tcp_info.payload": {"$ne": b''}})

    print("In total {} client->server test-qualifying traces on {}.".format(len(traces), test))

    non_uniform = 0
    uniform = 0
    entropy_non_uniform = 0
    entropy_uniform = 0
    for t in traces:
        if t['tcp_info'] is None:
            continue

        payload = b64decode(t['tcp_info']['payload'])
        if len(payload) > 149:
            p = analyser.kolmogorov_smirnov_uniform_test(payload[:2048])
            if p < 0.1:
                non_uniform += 1
            else:
                uniform += 1
            p = analyser.kolmogorov_smirnov_dist_test(payload[:2048], 8)
            if p < 0.1:
                entropy_non_uniform += 1
            else:
                entropy_uniform += 1


    print("Byte Non-uniform: {}; uniform: {}.".format(non_uniform, uniform))
    print("Entropy Non-uniform: {}; uniform: {}.".format(entropy_non_uniform, entropy_uniform))

    m.delete_collection(name)
