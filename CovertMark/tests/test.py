from data import parser, mongo
import os, sys

# Temporary test script, not an actual test.

parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
example_path = os.path.join(parent_path, 'examples', 'example.pcap')

a = parser.PCAPParser(example_path)
packets = a.load_packet_info()
print(packets[:20])

name = a.load_and_insert_new("Test collection.")
m = mongo.MongoDBManager()
print(m.lookup_collection(name))
print(m.find_traces(name, {}, 20))
