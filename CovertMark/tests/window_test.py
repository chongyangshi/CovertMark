from data import parser, mongo, constants
from analytics import traffic

import os, sys

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
long_path = os.path.join(parent_path, 'examples', 'local')

a = parser.PCAPParser(os.path.join(long_path, 'unobfuscated_acstest.pcap'))
name = a.load_and_insert_new("Windowing test.")
traces = m.find_traces(name, {}, max_r=1000)
traces1 = traffic.window_traces_fixed_size(traces, 50, source_ip='128.232.17.20')
traces2 = traffic.window_traces_time_series(traces, 50000, sort=False, source_ip='128.232.17.20')

for t in traces1:
    print(len(t))
print()
for t in traces2:
    print(len(t))

a.clean_up(name)
