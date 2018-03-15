import os
from json import load, dump
from importlib import import_module
import random, string
from collections import Counter

import data, strategy
import constants

def read_strategy_map():
    """
    Read in the strategy map from strategy/strategy_map.json.
    :returns: (succ, msg) -- succ = strategy_map if valid strategy map, False
        otherwise -- with msg containing the error found.
    """

    strategy_map = os.path.join(os.path.dirname(os.path.realpath(__file__)), "strategy", "strategy_map.json")
    if not data.utils.check_file_exists(strategy_map):
        return False, "No strategy map: strategy/strategy_map.json does not exist."

    try:
        strategies = load(open(strategy_map, 'r'))
    except:
        return False, "Invalid strategy map: JSON in strategy/strategy_map.json is invalid."

    if len(strategies) == 0:
        return False, "No strategy found in strategy map: strategy/strategy_map.json."

    # Process the strategy map.
    for name, strat in strategies.items():

        for c, t in strategy.constants.STRATEGY_FIELDS:
            if c not in strat or not isinstance(strat[c], t):
                return False, "The required field " + c + " is missing or invalid in strategy " + name + "."

        # As we have already imported strategy, check if all specified strategy
        # classes exist.
        if strat["module"] not in dir(strategy):
            return False, "The module specified by strategy " + name + " is missing."
        else:
            if strat["object"] not in dir(import_module(strategy.__name__ + '.' + strat["module"])):
                return False, "The strategy class specified by strategy " + name + " is missing."

        pt_filters_len = len(strat["pt_filters"])
        neg_filters_len = len(strat["negative_filters"])

        # These are the parameters always applied to the strategy.run(..) call.
        for i in strat["fixed_params"]:
            if len(i) != 2 or not i[0].isidentifier():
                return False, "The fixed parameters specified by strategy " + name + " are invalid."

        # Check defined filters:
        for i, w in enumerate(strat["pt_filters"]):
            if w in strategy.constants.JSON_FILTERS:
                strat["pt_filters"][i] = strategy.constants.JSON_FILTERS[w]
            else:
                return False, "Invalid PT filter found in strategy " + name + "."

        for i, w in enumerate(strat["negative_filters"]):
            if w in strategy.constants.JSON_FILTERS:
                strat["negative_filters"][i] = strategy.constants.JSON_FILTERS[w]
            else:
                return False, "Invalid negative filter found in strategy " + name + "."

        for r in strat["runs"]:

            for c, t in strategy.constants.RUN_FIELDS:
                if c not in r or not isinstance(r[c], t):
                    return False, "The required field " + c + " is missing or invalid in run " + str(r["run_order"]) +  " of strategy " + name + "."

            for i, w in enumerate(r["pt_filters_map"]):
                if w in strategy.constants.JSON_FILTERS:
                    r["pt_filters_map"][i] = strategy.constants.JSON_FILTERS[w]
                else:
                    return False, "A PT filter is missing or invalid in run " + str(r["run_order"]) +  " of strategy " + name + "."

            if len(r["pt_filters_map"]) != pt_filters_len:
                return False, "Mismatch of strategy PT filters with their mappings in run " + str(r["run_order"]) +  " of strategy " + name + "."

            for i, w in enumerate(r["negative_filters_map"]):
                if w in strategy.constants.JSON_FILTERS:
                    r["negative_filters_map"][i] = strategy.constants.JSON_FILTERS[w]
                else:
                    return False, "A negative filter is missing or invalid in run " + str(r["run_order"]) +  " of strategy " + name + "."

            if len(r["negative_filters_map"]) != neg_filters_len:
                return False, "Mismatch of strategy negative filters with their mappings in run " + str(r["run_order"]) +  " of strategy " + name + "."

            # These are the parameters applied to the strategy.run(..) call with
            # only expected int/str/bool type defined, requiring the user to
            # supply before the start of the runs.
            for i, w in enumerate(r["user_params"]):
                if len(w) != 2:
                    return False, "A user-defined parameter invalid in run " + str(r["run_order"]) +  " of strategy " + name + "."
                elif not w[0].isidentifier() or w[1] not in strategy.constants.JSON_OPT_PARAM_TYPES:
                    return False, "A user-defined parameter invalid in run " + str(r["run_order"]) +  " of strategy " + name + "."
                else:
                    r["user_params"][i] = [w[0], strategy.constants.JSON_OPT_PARAM_TYPES[w[1]]]

    return strategies, "Successfully parsed strategy/strategy_map.json."


def check_write_permission(path):
    """
    Check whether it is possible for the program to write to the path supplied.
    :returns: True if write permissible, False otherwise.
    """

    test_file = "test_" + ''.join([random.choice(string.ascii_letters) for _ in range(8)])
    test_file = os.path.join(path, test_file)

    try:
        open(test_file, 'w')
        os.remove(test_file) # Not sure if this will make antivirus unhappy.
    except PermissionError:
        return False

    return True


def validate_procedure(procedure, strategy_map):
    """
    Validate an imported CovertMark procedure.
    :param procedure: an imported CovertMark procedure.
    :param strategy_map: a strategy map validated by covertmark.py.
    :returns: (succ, msg) -- succ = True if the procedure is semantically valid,
     False otherwise; with msg indicating errors found.
    """

    mongo_reader = data.retrieve.Retriever() # For validating collections.

    if len(procedure) == 0:
        return False, "The imported procedure is empty."

    for run in procedure:

        if any([i not in run for i in constants.PROCEDURE_RUN_FIELDS]):
            return False, "A specified run in strategy script " + run["strategy"] + " is missing required field(s)."

        if run["strategy"] not in strategy_map:
            return False, "The specified strategy script " + run["strategy"] + " is not found in this build."

        strategy = strategy_map[run["strategy"]]

        run_found = False
        for r in strategy["runs"]:
            if r["run_order"] == run["run_order"]:
                matched_run = r
                run_found = True

        if not run_found:
            return False, "A specified run in strategy " + run["strategy"] + " cannot be found."

        if len(run["user_params"]) != len(matched_run["user_params"]):
            return False, "Mismatching user parameters supplied in strategy " + run["strategy"] + "."

        for param in run["user_params"]:
            matching_params = [i for i in matched_run["user_params"] if i[0] == param[0] and type(param[1]) == i[1]]
            if len(matching_params) != 1:
                return False, "Incorrect specification of user parameter " + param + "."

        pt_pcap_valid = data.utils.check_file_exists(os.path.expanduser(run["pt_pcap"])) and\
         Counter([i[1] for i in run["pt_filters"]]) == Counter(matched_run["pt_filters_map"])
        pt_collection_valid = mongo_reader.select(run["pt_collection"])

        if not (pt_pcap_valid or pt_collection_valid):
            return False, "Neither the supplied PT pcap file and filters, nor an existing PT collection is valid."

        # Skip validating negative inputs if not required by the strategy.
        if not strategy["negative_input"]:
            continue

        neg_pcap_valid = data.utils.check_file_exists(os.path.expanduser(run["neg_pcap"])) and\
         Counter([i[1] for i in run["neg_filters"]]) == Counter(matched_run["negative_filters_map"])
        neg_collection_valid = mongo_reader.select(run["neg_collection"])

        if not (neg_pcap_valid or neg_collection_valid):
            return False, "Neither the supplied negative pcap file and filters, nor an existing negative collection is valid."


    return True, "The procedure is successfully validated."


def save_procedure(export_path, procedure, strategy_map):
    """
    Save a programmed CovertMark procedure into the path specified for later
    retrieval.
    :param export_path: a qualified system path for exporting the procedure.
    :param procedure: a procedure generated by covertmark.py.
    :param strategy_map: a strategy map validated by covertmark.py.
    :returns: True if successfully saved, False otherwise or if procedure invalid.
    """

    # First check if this is a valid procedure.
    val, _ = validate_procedure(procedure, strategy_map)
    if not val:
        return False

    # Check the export path is valid and writable.
    export_path = os.path.expanduser(export_path.strip())
    if not export_path.endswith(".json"):
        return False

    if data.utils.check_file_exists(export_path):
        return False

    if not check_write_permission(os.path.dirname(export_path)):
        return False

    for run in procedure:
        if run["pt_collection"] != "" or run["neg_collection"] != "":
            print("Note: some or all of your strategy runs configured in this procedure import existing collections from MongoDB, this saved procedure will thus not be portable between systems.")

    try:
        with open(export_path, 'w') as export_file:
            dump(procedure, export_file)
    except:
        return False

    return True


def import_procedure(import_path, strategy_map):
    """
    Import from file a saved procedure and validate it.
    :param import_path: a qualified path leading to a json procedure file
        saved by CovertMark.
    :param strategy_map: a strategy map validated by covertmark.py.
    :returns: the validated procedure if successfully imported, False otherwise
     or if procedure invalid.
    """

    import_path = os.path.expanduser(import_path.strip())
    if not data.utils.check_file_exists(import_path):
        return False

    try:
        with open(import_path, "r") as procedure_file:
            procedure = load(procedure_file)
    except:
        return False

    if not validate_procedure(procedure, strategy_map):
        return False

    return procedure
