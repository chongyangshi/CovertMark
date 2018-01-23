import os
import socket
import ipaddress

from dpkt import tcp

def check_file_exists(file_path):
    """
    Check whether the file at file_path exists.

    :param file_path: full path to the file checked.
    :returns: a boolean indicating whether the file exists.
    """

    if os.path.isfile(file_path):
        return True
    else:
        return False


def parse_ip(ip_bytes):
    """
    Convert an IPv4/IPv6 address in bytes to an ipaddress object.
    :param ip_bytes: bytes of IPv4/IPv6 address.
    :returns: IP in string format, None if input invalid.
    """

    return_ip = None
    try:
        return str(ipaddress.ip_address(ip_bytes))
    except ValueError:
        return None


def build_subnet(subnet_str):
    """
    Convert an IPv4/IPv6 subnet in string format (e.g. 192.168.1.0/24) into an
    ipaddress IPv4Network/IPv6Network object.
    :param subnet_str: subnet in string format.
    :returns: IPv4Network/IPv6Network object depends on input type, None if
    input invalid.
    """

    try:
        network = ipaddress.IPv4Network(subnet_str)
    except ipaddress.AddressValueError:
        try:
            network = ipaddress.IPv6Network(subnet_str)
        except ipaddress.AddressValueError:
            return None

    return network


def parse_tcp_flags(flag_bits):
    """
    Parse flags of a TCP packet.
    :param flag_bytes: bits of of TCP packet flags, at least 8 bits.
    :returns: a dict of TCP flags and their values.
    """

    flags = {}

    # Based on dpkt manual by Jeff Silverman.
    flags["FIN"] = (flag_bits & tcp.TH_FIN) != 0
    flags["SYN"] = (flag_bits & tcp.TH_SYN) != 0
    flags["RST"] = (flag_bits & tcp.TH_RST) != 0
    flags["PSH"] = (flag_bits & tcp.TH_PUSH) != 0
    flags["ACK"] = (flag_bits & tcp.TH_ACK) != 0
    flags["URG"] = (flag_bits & tcp.TH_URG) != 0
    flags["ECE"] = (flag_bits & tcp.TH_ECE) != 0
    flags["CWR"] = (flag_bits & tcp.TH_CWR) != 0

    return flags
