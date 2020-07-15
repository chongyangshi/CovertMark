"""
This module stores constants used during the operations of the UI.
"""

# Application info.
CM_NAME = "CovertMark"
CM_VER = "0.1"
CM_RELEASE = "alpha"
CM_AUTHOR = "C Shi"
CM_LINK = "https://github.com/chongyangshi"
CM_LICENSE = "Please see LICENSE.md for terms of usage of this program."
CM_TITLE = """\
 _____                     _  ___  ___           _
/  __ \                   | | |  \/  |          | |
| /  \/ _____   _____ _ __| |_| .  . | __ _ _ __| | __
| |    / _ \ \ / / _ | '__| __| |\/| |/ _` | '__| |/ /
| \__/| (_) \ V |  __| |  | |_| |  | | (_| | |  |   <
 \____/\___/ \_/ \___|_|   \__\_|  |_/\__,_|_|  |_|\_\\
"""

DIVIDER = "-" * 40

PROCEDURE_RUN_FIELDS = ["strategy", "run_order", "user_params", "pt_pcap",
 "pt_filters", "pt_collection", "neg_pcap", "neg_filters", "neg_collection",
 "user_defined_name"]

# UI colours.
class colours:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    PURPLE = '\033[95m'
    RED = '\033[91m'
    GRAY = '\033[90m'
    BGC = "\033[;7m"
    BOLD = '\033[1m'
    ENDC = '\033[0m'

RATINGS = {
    (0, 75.0): (colours.GREEN, "This strategy is not very effective in identifying this obfuscation protocol."),
    (75.0, 90.0): (colours.PURPLE, "This strategy is reasonably effective in identifying this obfuscation protocol, and can be deployed by a state censor with some difficulties."),
    (90.0, 100.0): (colours.RED, "This strategy is very effective in identifying this obfuscation protocol, and can be easily deployed by a state censor.")
}

RATING_BANDS = {
    (0, 75.0): "Good Covertness",
    (75.0, 90.0): "Reasonable Covertness",
    (90.0, 100.0): "Bad Covertness"
}
