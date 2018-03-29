# Filter the input packet to preserve traffic between certain IP addresses or subnets only.
# python -m CovertMark.scripts.pcap_cleaner pcap_in.pcap pcap_out.pcap {IPs separated by space}
import dpkt
import sys, os

from ..data import utils

argvs = sys.argv

if len(argvs) < 4:
    print("Usage: python -m CovertMark.scripts.pcap_cleaner pcap_in.pcap pcap_out.pcap {IPs separated by ','}")
    sys.exit(1)

if not utils.check_file_exists(os.path.abspath(argvs[1])):
    print("Error: input PCAP does not exist.")
    sys.exit(1)

if not utils.get_full_path(os.path.abspath(argvs[2])):
    print("Error: path for output PCAP is not valid.")
    sys.exit(1)

if utils.check_file_exists(os.path.abspath(argvs[2])):
    print("Error: output PCAP already exists.")
    sys.exit(1)

filter_nets = [utils.build_subnet(i) for i in argvs[3:]]
if not all(filter_nets):
    print("Error: some IP addresses or subnets supplied are not valid.")
    sys.exit(1)

packets_to_write = []
read = 0
accepted = 0
try:
    with open(argvs[1], 'rb') as f:
        for ts, buf in dpkt.pcap.Reader(f):
            read += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                dst = utils.parse_ip(ip.dst)
                src = utils.parse_ip(ip.src)
                dst_match = any([n.overlaps(utils.build_subnet(dst)) for n in filter_nets])
                src_match = any([n.overlaps(utils.build_subnet(src)) for n in filter_nets])
                if dst_match and src_match: # Only packets from *and* to interested parties.
                    packets_to_write.append((buf, ts))
                    accepted += 1
            except: # If not Ethernet packet or other read issues.
                continue
except:
    print("Error: invalid data or format in input PCAP.")
    sys.exit(1)

print("Read {} packets from {}.".format(read, argvs[1]))
print("Writing {} matching packets to {}.".format(accepted, argvs[2]))

try:
    with open(argvs[2], 'wb') as f:
        output_writer = dpkt.pcap.Writer(f)
        for buf, ts in packets_to_write:
            output_writer.writepkt(buf, ts=ts)
        output_writer.close()
except:
    print("Error: an error has been encountered when writing to the output PCAP.")
    sys.exit(1)

print("Successfully written to {}.".format(argvs[2]))
