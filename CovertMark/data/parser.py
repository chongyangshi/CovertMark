from data import utils, constants, mongo

from os.path import isfile
from base64 import b64encode, b64decode
import dpkt


class PCAPParser:

    def __init__(self, pcap_file):

        if not utils.check_file_exists(pcap_file):
            raise FileNotFoundError("PCAP file not found: " + pcap_file)

        self._pcap_file = pcap_file
        self.__db = mongo.MongoDBManager(db_server=constants.MONGODB_SERVER)


    def load_packet_info(self):
        """
        Load and return information of packet traces.
        Non-IP/IPv6 packets are ignored.
        Format: ```[{type: v4/v6, dst: dst_ip, src: src_ip, len: packet_length,
                    proto: protocol, time: time_stamp, ttl: TTL/hop_limit,
                    tcp_info (None for non-TCP packets):
                        {sport: src_port, dport: dst_port, flags: tcp_flags,
                        opts: tcp_options, seq: tcp_seq, ack: tcp_ack,
                        payload: b64encoded_payload},
                    tls_info (None for non-TLS packets):
                        {type: tls_type, ver: tls_version, len: tls_data_length,
                        records: tls_num_records, data: b64_encoded_tls_data
                        (first record)}
                }]```
        :returns: a list of packets parsed formatted as above.
        """

        packet_list = []

        with open(self._pcap_file, 'rb') as f:
            for ts, buf in dpkt.pcap.Reader(f):
                eth = dpkt.ethernet.Ethernet(buf)
                packet_info = {}

                # Generic IP information.
                ip = eth.data
                if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                    packet_info["dst"] = utils.byte_to_str(ip.dst, "IP")
                    packet_info["src"] = utils.byte_to_str(ip.src, "IP")
                    packet_info["type"] = "IPv4"
                    packet_info["len"] = ip.len
                    packet_info["ttl"] = ip.ttl

                elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                    packet_info["dst"] = utils.byte_to_str(ip.dst, "IP6")
                    packet_info["src"] = utils.byte_to_str(ip.src, "IP6")
                    packet_info["type"] = "IPv6"
                    packet_info["len"] = ip.plen
                    packet_info["ttl"] = ip.hlim

                else:
                    PCAPParser.log_invalid("Non ip/ip6 packet ignored: " + str(buf))

                packet_info["proto"] = type(ip.data).__name__
                packet_info["time"] = "{0:.6f}".format(ts)

                # Check and record TCP information if applicable.
                tcp_info = None
                if packet_info["proto"] == "TCP":
                    tcp_info = {}
                    tcp_info["sport"] = ip.data.sport
                    tcp_info["dport"] = ip.data.dport
                    tcp_info["flags"] = utils.parse_tcp_flags(ip.data.flags)
                    tcp_info["opts"] = dpkt.tcp.parse_opts(ip.data.opts)
                    tcp_info["ack"] = ip.data.ack
                    tcp_info["seq"] = ip.data.seq
                    tcp_info["payload"] = b64encode(ip.data.data)
                packet_info["tcp_info"] = tcp_info

                # Check and record TLS information if applicable.
                try:
                    tls_data = dpkt.ssl.TLS(tcp.data)
                    tls_data["type"] = constants.TLS_TYPE[tls.type]
                    tls_data["ver"] = constants.TLS_VERSION[tls.version]
                    tls_data["len"] = tls.len
                    tls_data["records"] = len(tls_records)
                    if tls_data["records"] > 0:
                        tls_data["data"] = b64encode(tls.records[0].data)
                    # A vast majority of TLS packets have only one record, and
                    # in multi-record case this tends to contain the majority
                    # payload. As a secondary information, the number of records
                    # is recorded for each TLS packet.
                except:
                    tls_data = None
                packet_info["tls_info"] = tls_data

                packet_list.append(packet_info)

        return packet_list


    def load_and_insert_new(self, description=""):
        """
        Load packet traces from pcap file, and insert into a new collection.
        :param description: description of the new collection, empty by default.
        :returns: name of the new collection, False if failed.
        """

        traces = self.load_packet_info()
        insertion_result = self.__db.insert_traces(traces)

        if insertion_result:
            collection_name = insertion_result["collection_name"]
            self.__db.modify_collection_description(collection_name, description)
            return collection_name
        else:
            return False


    def load_and_insert_existing(self, collection_name):
        """
        Load packet traces from pcap file, and insert into an existing collection.
        :returns: True if insertion successful, False if failed.
        """

        traces = self.load_packet_info()
        insertion_result = self.__db.insert_traces(traces, collection_name=collection_name)

        if insertion_result:
            collection_name = insertion_result["collection_name"]
            return collection_name
        else:
            return False


    @staticmethod
    def log_invalid(error_content):
        """
        Utility function to log invalid packet information parsed.
        :returns: None
        """
        if constants.LOG_ERROR and isfile(constants.LOG_FILE):
            with open(constants.LOG_FILE, "a") as log_file:
                log_file.write(error_content)
