from data import parser, mongo
from analytics import entropy

import os, sys
from base64 import b64decode

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
analyser = entropy.EntropyAnalyser()

for test in ['obfs4', 'unobfuscated']:
    example_path = os.path.join(parent_path, 'examples', test + '.pcap')
    a = parser.PCAPParser(example_path)
    #a.set_ip_filter(['37.218.245.14'])
    name = a.load_and_insert_new("Test collection.")

    print("{} traces with {}.".format(m.count_traces(name, {}), test))

    traces = m.find_traces(name, {})

    non_uniform = 0
    uniform = 0
    for t in traces:
        if t['tcp_info'] is None:
            continue

        payload = b64decode(t['tcp_info']['payload'])
        if len(payload) > 8:
            p = analyser.kolmogorov_smirnov_dist_test(payload, 8)
            if p < 0.1:
                non_uniform += 1
            else:
                uniform += 1

    print("Non-uniform: {}; uniform: {}.".format(non_uniform, uniform))

    m.delete_collection(name)
