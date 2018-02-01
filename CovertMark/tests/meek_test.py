from data import parser, mongo, constants
from analytics import traffic

import os, sys
from base64 import b64decode

# Temporary test script, not an actual test.

m = mongo.MongoDBManager()
parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
long_path = os.path.join(parent_path, 'examples', 'local')

a = parser.PCAPParser(os.path.join(long_path, 'meeklong.pcap'))
a.set_ip_filter([('192.168.0.42', constants.IP_SRC), ('13.32.68.163', constants.IP_DST)])
name = a.load_and_insert_new("meek")
total = m.count_traces(name, {})
print("In total {} client->server traces by meek.".format(total))

traces = m.find_traces(name, {"tls_info": {"$ne": None}})
for trace in traces: # To be done in data.retrieve when properly implemented.
    trace['tcp_info']['payload'] = b64decode(trace['tcp_info']['payload'])
most_frequent = traffic.ordered_tcp_payload_length_frequency(traces, True)

top_cluster = most_frequent[0]
top_two_clusters = top_cluster.union(most_frequent[1])

a = parser.PCAPParser(os.path.join(long_path, 'unobfuscatedlong.pcap'))
a.set_ip_filter([('172.28.195.198', constants.IP_SRC)])
name = a.load_and_insert_new("unobfuscated")
total = m.count_traces(name, {"tcp_info": {"$ne": None}})
all_dst_ips = m.distinct_traces(name, 'dst')
print("In total {} client->server unobfuscated traces.".format(total))

traces = m.find_traces(name, {"tls_info": {"$ne": None}})
top = 0
top2 = 0
ips_blocked = set([])
ips_blocked_2 = set([])
for trace in traces: # To be done in data.retrieve when properly implemented.
    payload_len = len(b64decode(trace['tcp_info']['payload']))
    if payload_len in top_cluster:
        top += 1
        ips_blocked.add(trace['dst'])
    elif payload_len in top_two_clusters:
        top2 += 1
        ips_blocked_2.add(trace['dst'])

print("---")
print("Top cluster False Positive Rate: {} out of {} client->server traces ({:0.2f}%)".format(top, total, float(top)/total*100))
print("Top cluster blocked IPs: {} out of {} ({:0.2f}%).".format(len(ips_blocked), all_dst_ips, float(len(ips_blocked))/all_dst_ips*100))
print("---")
print("Top two clusters False Positive Rate: {} out of {} client->server traces ({:0.2f}%)".format(top2, total, float(top2)/total*100))
print("Top two clusters blocked IPs: {} out of {} ({:0.2f}%).".format(len(ips_blocked_2), all_dst_ips, float(len(ips_blocked_2))/all_dst_ips*100))

wireshark_output = "Top cluster blocked Wireshark: tcp.payload && ("
for i, ip in enumerate(list(ips_blocked)):
    wireshark_output += "ip.dst_host == \"" + ip + "\" "
    if i < len(ips_blocked) - 1:
        wireshark_output += "|| "
wireshark_output += ") && ("
for i, l in enumerate(list(top_cluster)):
    wireshark_output += "tcp.len == " + str(l)
    if i < len(top_cluster) - 1:
        wireshark_output += " || "
wireshark_output += ")"
print(wireshark_output)

wireshark_output = "Top two clusters blocked Wireshark: tcp.payload && ("
for i, ip in enumerate(list(ips_blocked_2)):
    wireshark_output += "ip.dst_host == \"" + ip + "\" "
    if i < len(ips_blocked_2) - 1:
        wireshark_output += "|| "
wireshark_output += ") && ("
for i, l in enumerate(list(top_two_clusters)):
    wireshark_output += "tcp.len == " + str(l)
    if i < len(top_two_clusters) - 1:
        wireshark_output += " || "
wireshark_output += ")"
print(wireshark_output)
