import os, sys
from importlib import import_module

import data, analytics, strategy
import constants as c
import utils

# Reader for listing collections.
reader = data.retrieve.Retriever()

# Check if the strategy map is still good.
good_json, reason = utils.read_strategy_map()
if not good_json:
    print("strategy/strategy_map.json is invalid after customisation, due to: ")
    print(reason)
    print("exiting...")
    sys.exit(1)

# Main titles!
print(c.CM_TITLE)
print(" " * 20 + c.CM_NAME + " " + c.CM_VER + c.CM_RELEASE + "\n")
print("(c) " + c.CM_AUTHOR + " (" + c.CM_LINK + ") and contributors")
print(c.CM_LICENSE)
print(c.DIVIDER)
