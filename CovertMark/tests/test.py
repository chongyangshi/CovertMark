from data import parser, mongo
from analytics import entropy

import os, sys
from base64 import b64decode

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

for test in ['example', 'meek']:
    example_path = os.path.join(parent_path, 'examples', test + '.pcap')
    a = parser.PCAPParser(example_path)
    #a.set_ip_filter(['13.33.51.0/24'])
    name = a.load_and_insert_new("Test collection.")
    print(m.count_traces(name, {}))

    traces = m.find_traces(name, {})

    for t in traces:
        if t['tls_info'] is not None:
            if t['tls_info']['records'] > 0:
                for d in t['tls_info']['data']:
                    print(entropy.byte_entropy(d), t['src'], t['dst'])


    m.delete_collection(name)
