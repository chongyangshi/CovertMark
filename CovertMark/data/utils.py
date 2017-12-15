import os
import socket

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


def byte_to_str(ip_bytes, ip_type):
    """
    Convert an IPv4/IPv6 address in bytes to readable string.
    :param ip_bytes: bytes of IPv4/IPv6 address.
    :param ip_type: "IP" or "IP6" for iPv4 or IPv6 respectively.
    :returns: readable IPv4/IPv6 address as a string. None if invalid address.
    """

    return_ip = None
    try:
        if ip_type == "IP":
            return_ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
        elif ip_type == "IP6":
            return_ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
    except:
        raise
        pass

    return return_ip


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
