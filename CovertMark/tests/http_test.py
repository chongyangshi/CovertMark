from data import parser, mongo, constants

import os, sys

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
long_path = os.path.join(parent_path, 'examples', 'local')

a = parser.PCAPParser(os.path.join(long_path, 'unobfuscatedlongext.pcap'))
name = a.load_and_insert_new("http")
total = m.count_traces(name, {})
print("In total {} client->server HTTP traces.".format(total))
traces = m.find_traces(name, {"http_info": {"$ne": None}})

for t in traces:
    print(t)

a.clean_up(name)
