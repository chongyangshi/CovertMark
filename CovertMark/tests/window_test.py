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
traces1 = traffic.window_traces_fixed_size(traces, 100)
traces2 = traffic.window_traces_time_series(traces, 50000, sort=False)

print(traffic.get_window_stats(traces1[0], '128.232.17.20'))
print(traffic.get_window_stats(traces2[-1], '128.232.17.20'))

a.clean_up(name)
