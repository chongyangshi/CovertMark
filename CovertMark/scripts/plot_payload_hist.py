# Plot TCP payload distribution of packets in a stored collection.
from ..data import retrieve, utils, plot
from ..analytics import constants

from sys import exit

retriever = retrieve.Retriever()
collections = retriever.list()
print(retriever.list(True))

name = input("Enter the collection name for plotting the histogram: ").strip()
if not retriever.select(name):
    print("Invalid collection name, exiting.")
    exit(1)

tls_mode = input("Only look at packets with valid TLS records ('only'), or all packets ('all')?: ").strip()
if tls_mode not in ["only", "all"]:
    print("Invalid TLS mode, exiting.")
    exit(1)

print("Reading packets from selected collection...")
packets = retriever.retrieve()
lengths = []
total = 0
total_plotted = 0
for packet in packets:
    total += 1

    if packet["tcp_info"] is None:
        continue

    if len(packet["tcp_info"]["payload"]) <= 0:
        continue
    
    if tls_mode == "only" and packet["tls_info"] is None:
        continue

    if len(packet["tcp_info"]["payload"]) > constants.MTU_FRAME_AVOIDANCE_THRESHOLD:
        continue

    lengths.append(len(packet["tcp_info"]["payload"]))
    total_plotted += 1

print("Processed {} qualifying packets out of {} stored.".format(total_plotted, total))

x_name = input("Label on the x-axis: ").strip()
y_name = input("Label on the y-axis: ").strip()
title = input("Title of the histogram: ").strip()
out_path = utils.get_full_path(input("Where to put the histogram file?: ").strip())

print("Plotting...")
plot.plot_hist(lengths, x_name, y_name, show=False, img_out=out_path, title=title)

print("Finished.")