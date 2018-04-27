Captured network traces
=======================

The followed are lists of proxy traffic traces and unobfuscated
(regular) traffic traces captured for testing and evaluation of
CovertMark during the project. All traffic were captured under realistic
internet browsing conditions on the modern web, which were carried out
by real humans. This marks the greatest distinction between the
CovertMark datasets and datasets used in prior protocol-obfuscation-detection
researches.

Sources and destinations of packets have been scrambled with
`Crypto-PAn <https://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/>`__,
which is primarily to protect the exact addresses of Tor PT bridges in
proxy traces. Regular traffic captured as controls and negative training
data were produced by human volunteers under experimental conditions with detailed instructions to
protect their privacy. All unencrypted and non-TCP traffic have also
been stripped out. However, in contrast with `CAIDA
traces <http://www.caida.org/data/>`__, all encrypted payloads have been
preserved, along with some cleartext metadata such as TLS SNI
hostnames. This allows CovertMark to examine encrypted network traffic
from the exact perspective of state censors performing advanced DPI
detection of proxy servers.

Click on the file names below to download associated traces.

Proxy Traces
------------

All proxy traces are unaffected by TCP segmentation offload (TSO), with
longer-than-MTU payloads fully segmented.

+------------------+-----+-------------+-------------+---------------+
| File Name        | Pac\| IP(s) of    | IP(s) of    | Port(s) of    |
|                  | ket\| Proxy       | Proxy       | Proxy Servers |
|                  | s   | Clients     | Servers     |               |
+==================+=====+=============+=============+===============+
| `shadowsocks1_an\| 674\| 130.0.170.1\| 12.173.72.5\| 443, 995      |
| on <https://goo. | 458 | 8,          | 3,          |               |
| gl/DMShFW>`__    |     | 130.0.174.2\| 56.136.248.\|               |
|                  |     | 53          | 69          |               |
+------------------+-----+-------------+-------------+---------------+
| `shadowsocks2_an\| 286\| 130.0.175.1\| 213.69.160.\| 443           |
| on <https://goo. | 887 | 23          | 49          |               |
| gl/WcvBt4>`__    |     |             |             |               |
+------------------+-----+-------------+-------------+---------------+
| `meek1_anon <htt | 756\| 39.22.50.9, | 6.78.64.204\| 443           |
| ps://goo.gl/uM4i | 548 | 130.0.168.2\| , 35.130.16\|               |
| 6f>`__           |     | 47          | 8.244       |               |
+------------------+-----+-------------+-------------+---------------+
| `meek2_anon <htt | 602\| 39.22.56.17 | 6.97.147.45 | 443           |
| ps://goo.gl/Zp3a | 134 |             |             |               |
| Bq>`__           |     |             |             |               |
+------------------+-----+-------------+-------------+---------------+
| `obfs4-1_anon <h | 619\| 39.22.52.90 | 20.234.236.\| 443, 38224    |
| ttps://goo.gl/1z | 754 | ,           | 206,        |               |
| F8op>`__         |     | 207.52.86.2\| 109.45.76.1\|               |
|                  |     | 3           | 94          |               |
+------------------+-----+-------------+-------------+---------------+
| `obfs4-2_anon <h | 373\| 130.0.171.1\| 20.234.236.\| 38224         |
| ttps://goo.gl/FK | 504 | 96          | 206         |               |
| qD5U>`__         |     |             |             |               |
+------------------+-----+-------------+-------------+---------------+

Negative / Regular Traffic Traces
---------------------------------

The longer, multi-client ``cantab_anon.pcap`` was captured on machines
with TCP segmentation offloading due to technical limitations, which
means that longer-than-MTU payloads will appear unsegmented. This does
not however affect CovertMark’s default detection strategies. The
shorter, single-client ``lso_anon.pcap`` is unaffected with all longer-than-MTU
payloads properly segmented.

+-----------------+-----------------+-----------------+-----------------+
| File Name       | Packets         | Concurrent      | Client          |
|                 |                 | Users           | IP’s/Subnets    |
+=================+=================+=================+=================+
| `lso_anon <http | 200405          | 1               | 130.0.169.136/3\|
| s://goo.gl/ZZnE |                 |                 | 2               |
| Zz>`__          |                 |                 |                 |
+-----------------+-----------------+-----------------+-----------------+
| `cantab_anon <h | 1566737         | 5               | 171.69.236.0/24 |
| ttps://goo.gl/8 |                 |                 |                 |
| vSe8i>`__       |                 |                 |                 |
+-----------------+-----------------+-----------------+-----------------+
