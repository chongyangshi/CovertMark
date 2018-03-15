import os, sys
from importlib import import_module
from tabulate import tabulate

import data, analytics, strategy
import constants as c
import utils

# Reader for listing collections.
reader = data.retrieve.Retriever()

# Check if the strategy map is still good.
strategy_map, reason = utils.read_strategy_map()
if not strategy_map:
    print("strategy/strategy_map.json is invalid after customisation, due to: ")
    print(reason)
    print("exiting...")
    sys.exit(1)

# Main titles!
print(c.CM_TITLE)
print(" " * 18 + c.CM_NAME + " " + c.CM_VER + c.CM_RELEASE + "\n")
print("(c) " + c.CM_AUTHOR + " (" + c.CM_LINK + ") and contributors")
print(c.CM_LICENSE)
print("A terminal of at least 3/4 screen width is recommended.")
print(c.DIVIDER)

# Collect runs of all strategies for the user to choose.
print("The following runs of strategies are implemented and available: ")
available_runs = [] # (selection_id, strategy_name, run_description)
available_runs_header = ("Run ID", "Strategy Name", "Strategy Run Description")
available_runs_indices = [] # (strategy_map_key, run_order)
selection_id = 0
for strategy_map_key, strat in strategy_map.items():
    strategy_class = getattr(getattr(strategy, strat["module"]), strat["object"])
    strategy_name = strategy_class.NAME
    for run in strat["runs"]:
        available_runs.append((selection_id, strategy_name, run["run_description"]))
        available_runs_indices.append((strategy_map_key, run["run_order"]))
        selection_id += 1

print(tabulate(available_runs, available_runs_header, tablefmt="fancy_grid"))
