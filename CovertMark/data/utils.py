import os
import socket
import ipaddress
from json import load

from dpkt import tcp

def check_file_exists(file_path):
    """
    Check whether the file at file_path exists.

    :param str file_path: full path to the file checked.
    :returns: a boolean value indicating whether the file exists.
    """

    if os.path.isfile(file_path):
        return True
    else:
        return False


def get_full_path(file_path):
    """
    Given the path to a file, returns the full path containing the file by
    expanding any user prefixes. This does not require the target file to exist.

    :param str file_path: full or user-prefix path to file.
    :returns: the path to the directory containing the specified file. None if
        the directory does not exist.
    """

    directory = os.path.dirname(file_path)
    full_dir = os.path.expanduser(directory)

    if not os.path.isdir(full_dir):
        return None

    return os.path.join(full_dir, os.path.basename(file_path))


def read_mongo_credentials():
    """
    Reads and returns mongo credentials stored in mongo-auth.json.

    :returns: a dict containing `'username'` and `'password'` specified if read
        was successful, as well as `'auth_source'` for the authentication databse.
        Returns None if the JSON file does not exist or is invalid.
    """

    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mongo-auth.json')

    if not check_file_exists(file_path):
        return None

    try:
        creds = load(open(file_path, 'r'))
    except:
        return None

    for i in ['username', 'password', 'auth_source']:
        if i not in creds:
            return None

    return creds


def parse_ip(ip_bytes):
    """
    Convert an IPv4/IPv6 address in bytes to a valid IP address in string format,
        if it is indeed valid.

    :param bytes ip_bytes: bytes of IPv4/IPv6 address.
    :returns: IP address in string format, None if input invalid.
    """

    return_ip = None
    try:
        return str(ipaddress.ip_address(ip_bytes))
    except ValueError:
        return None


def build_subnet(subnet_str):
    """
    Convert an IPv4/IPv6 subnet in string format (e.g. 192.168.1.0/24) into an
    :class:`ipaddress.IPv4Network` or :class:`ipaddress.IPv6Network` object.

    :param str subnet_str: subnet in string format.
    :returns: :class:`ipaddress.IPv4Network` or :class:`ipaddress.IPv6Network`
        object depends on input subnet address type, or None if input invalid.
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

    :param bytes flag_bytes: a byte of bits containing TCP packet flag, only the
        first 8 bits are in use.
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
