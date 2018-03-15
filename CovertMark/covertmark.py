import os, sys
from importlib import import_module

import data, analytics, strategy
import constants
import utils

good_json, reason = utils.read_strategy_map()

if not good_json:
    print("strategy/strategy_map.json is invalid after customisation, due to: ")
    print(reason)
    print("exiting...")
    sys.exit(1)

# Now perform the rest of the setup.
reader = data.retrieve.Retriever()
