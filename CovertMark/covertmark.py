import os, sys
from importlib import import_module
from tabulate import tabulate
import argparse

import data, analytics, strategy
import constants as c
import utils, handler

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--import-saved", help="Import and execute a saved CovertMark benchmark procedure.", default="_")
args = parser.parse_args()

# Reader for listing collections.
reader = data.retrieve.Retriever()
current_results = [] # tuples of strategy instances and run configurations.

# Check if the strategy map is still good.
strategy_map, reason = utils.read_strategy_map()
if not strategy_map:
    print("strategy/strategy_map.json is invalid after modification, due to: ")
    print(reason)
    print("exiting...")
    sys.exit(1)

# Main titles!
print(c.CM_TITLE)
print(" " * 18 + c.CM_NAME + " " + c.CM_VER + c.CM_RELEASE + "\n")
print("(c) " + c.CM_AUTHOR + " (" + c.CM_LINK + ") and contributors")
print(c.CM_LICENSE)
print("A full screen width terminal is recommended.")
print(c.DIVIDER)

available_runs, run_indices = utils.get_strategy_runs(strategy_map)

load_existing = False
if args.import_saved != "_":
    if data.utils.check_file_exists(args.import_saved):
        load_existing = True

if load_existing:
    procedure = utils.import_procedure(args.import_saved, strategy_map)
    if not procedure:
        print(args.import_saved + " cannot be validated during import.")
        sys.exit(1)
    print("Executing imported procedure...\n")
    current_results, _ = utils.execute_procedure(procedure, strategy_map, db_sub=True)

else:
    # Collect runs of all strategies for the user to choose.
    print("The following runs of strategies are implemented and available: ")
    print(available_runs)

command_handler = handler.CommandHandler(strategy_map)
print("\nCommands available:")
command_handler.dispatch("help")
while True:
    command = input(c.CM_NAME + " >>> ").strip()
    if command == "exit":
        break
    if not command_handler.dispatch(command):
        print("Invalid command, enter `help` to get descriptions of available commands.")
    print()
