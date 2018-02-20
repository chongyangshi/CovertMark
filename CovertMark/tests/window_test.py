from data import parser, mongo, constants, utils
from analytics import traffic

import os, sys

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
long_path = os.path.join(parent_path, 'examples', 'local')

a = parser.PCAPParser(os.path.join(long_path, 'unobfuscated_acstest.pcap'))
name = a.load_and_insert_new("Windowing test.")
traces = m.find_traces(name, {})
windows = traffic.window_traces_time_series(traces, 60*1000000, sort=False)

clientnet = utils.build_subnet('128.232.17.20')

groups = []
for window in windows:
    grouped = traffic.group_traces_by_ip_fixed_size(window, [clientnet], 20)
    print([(i, len(grouped[i])) for i in grouped if len(grouped[i]) > 5]) # at least 5 segments in the minute with that remote host.
    groups.append(grouped)

print(traffic.get_window_stats(list(groups[-1].items())[-1][-1][-1], ['128.232.17.20']))

a.clean_up(name)
