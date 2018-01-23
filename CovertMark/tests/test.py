from data import parser, mongo
import os, sys
from base64 import b64decode

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

example_path = os.path.join(parent_path, 'examples', 'example.pcap')
a = parser.PCAPParser(example_path)
name = a.load_and_insert_new("Test collection.")
print(m.count_traces(name, {}))

example_path2 = os.path.join(parent_path, 'examples', 'meek.pcap')
b = parser.PCAPParser(example_path2)
b.load_and_insert_existing(name)
print(m.count_traces(name, {}))

#print(m.lookup_collection(name))
#traces = m.find_traces(name, {})

# for t in traces:
#     if t['tls_info'] is not None:
#         if t['tls_info']['records'] > 0:
#             for d in t['tls_info']['data']:
#                 print(b64decode(d))
