from data import utils, constants, mongo

from os.path import isfile
from base64 import b64encode, b64decode
import ipaddress
import dpkt


class PCAPParser:

    def __init__(self, pcap_file):

        if not utils.check_file_exists(pcap_file):
            raise FileNotFoundError("PCAP file not found: " + pcap_file)

        self._pcap_file = pcap_file
        self.__db = mongo.MongoDBManager(db_server=constants.MONGODB_SERVER)
        self.__filter = []


    def get_ip_filter(self):
        """
        Return the current ip filter configuration.
        :returns: a list of acceptable IPv4/IPv6 subnets in ipaddress subnet objects.
        """

        return self.__filter


    def set_ip_filter(self, subjects):
        """
        Configure the parser to only store a packet if its source or
        destination address belongs to an address or subnet as specified.
        Always process single addresses as lowest-level subnets for convenience.
        Calling this method overwrites the previous filter configuration.
        :param subjects: a list of acceptable IPv4/IPv6 addresses or subnets in
            string format, and their direction. Format: [(NET, POSITION)], where
            NET represents the IPv4/IPv6 address or subnet to track, and POSITION
            represents whether this is supposed to be IP_SRC or IP_DST.
        :returns: the number of successfully added filters, overlapping subnets
            are processed separately.
        """

        self.__filter = []
        for subject in subjects:

            if not isinstance(subject, tuple) or (subject[1] not in [constants.IP_SRC, constants.IP_DST]):
                continue

            subnet = utils.build_subnet(subject[0])
            if subnet:
                self.__filter.append((subnet, subject[1]))

        return len(self.__filter)


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
                        records: tls_num_records, data: [b64_encoded_tls_data]}
                }]```
        :returns: a list of packets parsed formatted as above.
        """

        packet_list = []

        check_filter = False
        if len(self.__filter) > 0:
            check_filter = True

        with open(self._pcap_file, 'rb') as f:
            for ts, buf in dpkt.pcap.Reader(f):
                eth = dpkt.ethernet.Ethernet(buf)
                packet_info = {}

                # Generic IP information.
                ip = eth.data
                if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                    packet_info["dst"] = utils.parse_ip(ip.dst)
                    packet_info["src"] = utils.parse_ip(ip.src)
                    packet_info["type"] = "IPv4"
                    packet_info["len"] = ip.len
                    packet_info["ttl"] = ip.ttl

                elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                    packet_info["dst"] = utils.parse_ip(ip.dst)
                    packet_info["src"] = utils.parse_ip(ip.src)
                    packet_info["type"] = "IPv6"
                    packet_info["len"] = ip.plen
                    packet_info["ttl"] = ip.hlim

                else:
                    PCAPParser.log_invalid("Non ip/ip6 packet ignored: " + str(buf))
                    continue

                # Drop this packet if filter set and this ip is not required by
                # the filter.
                if check_filter:
                    drop = True
                    src_net = utils.build_subnet(packet_info["src"])
                    dst_net = utils.build_subnet(packet_info["dst"])
                    for f in self.__filter:
                        if f[1] == constants.IP_SRC:
                            if src_net.overlaps(f[0]):
                                drop = False
                            else:
                                drop = True
                                break
                        elif f[1] == constants.IP_DST:
                            if dst_net.overlaps(f[0]):
                                drop = False
                            else:
                                drop = True
                                break
                    if drop:
                        continue

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
                    tls = dpkt.ssl.TLS(ip.data.data)
                    tls_data = {}
                    tls_data["type"] = constants.TLS_TYPE[tls.type]
                    tls_data["ver"] = constants.TLS_VERSION[tls.version]
                    tls_data["len"] = tls.len
                    tls_data["records"] = len(tls.records) # Number of records.
                    tls_data["data"] = []
                    for record in tls.records:
                        tls_data["data"].append(b64encode(record.data))
                except:
                    tls_data = None
                packet_info["tls_info"] = tls_data

                packet_list.append(packet_info)

        return packet_list


    def load_and_insert_new(self, description=""):
        """
        Load packet traces from pcap file, and insert into a new collection.
        N.B. Returned collection name must be verified to not be False.
        :param description: description of the new collection, empty by default.
        :returns: name of the new collection, False if failed.
        """

        traces = self.load_packet_info()
        if len(traces) == 0: # No packet loaded (likely incorrect ip filter.)
            return False

        insertion_result = self.__db.insert_traces(traces)

        if len(insertion_result["inserted"].inserted_ids) > 0:
            collection_name = insertion_result["collection_name"]
            self.__db.modify_collection_description(collection_name, description)
            return collection_name
        else:
            return False


    def load_and_insert_existing(self, collection_name):
        """
        Load packet traces from pcap file, and insert into an existing collection.
        N.B. Returned collection name must be verified to not be False.
        :returns: True if insertion successful, False if failed.
        """

        traces = self.load_packet_info()
        if len(traces) == 0: # No packet loaded (likely incorrect ip filter.)
            return False
        insertion_result = self.__db.insert_traces(traces, collection_name=collection_name)

        if len(insertion_result["inserted"].inserted_ids) > 0:
            return True
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
