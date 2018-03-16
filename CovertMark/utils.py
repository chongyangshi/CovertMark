import os, sys
from json import load, dump
from importlib import import_module
import random, string
from operator import itemgetter
from collections import Counter
from tabulate import tabulate

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

    if not procedure or "runs" not in procedure or len(procedure["runs"]) == 0:
        return False, "The imported procedure is empty."

    if any([i not in procedure for i in constants.PROCEDURE_META_FIELDS]):
        return False, "The procedure is missing required meta field(s)."

    # Check if we can re-parse the PT pcap if a collection is not specified in the run.
    pt_pcap_validated = False
    if procedure["pt_pcap"] != "":
        pt_pcap = os.path.expanduser(procedure["pt_pcap"])
        if data.utils.check_file_exists(pt_pcap):
            try:
                data.parser.PCAPParser(pt_pcap)
            except:
                return False, pt_pcap + " is not valid, pcapng is not supported by dpkt."
        else:
            return False, pt_pcap + " does not exist."
        pt_pcap_validated = True

    pt_filters_validated = False
    if procedure["pt_filters"] != []:
        pt_filters = procedure["pt_filters"]
        if not all([data.utils.build_subnet(i[0]) for i in pt_filters]):
            return False, "PT input filters are not valid IP addresses or subnets."
        pt_filters_validated = True

    if pt_pcap_validated and pt_filters_validated:
        pt_reparsing_possible = True
    else:
        pt_reparsing_possible = False

    # Check if we can re-parse the negative pcap if a collection is not specified in the run.
    neg_pcap_validated = False
    if procedure["neg_pcap"] != "":
        neg_pcap = os.path.expanduser(procedure["neg_pcap"])
        if data.utils.check_file_exists(neg_pcap):
            try:
                data.parser.PCAPParser(neg_pcap)
            except:
                return False, neg_pcap + " is not valid, pcapng is not supported by dpkt."
        else:
            return False, neg_pcap + " does not exist."
        neg_pcap_validated = True

    neg_filters_validated = False
    if procedure["neg_filters"] != []:
        neg_filters = procedure["neg_filters"]
        if not all([data.utils.build_subnet(i[0]) for i in neg_filters]):
            return False, "Negative input filters are not valid IP addresses or subnets."
        neg_filters_validated = True

    if neg_pcap_validated and neg_filters_validated:
        neg_reparsing_possible = True
    else:
        neg_reparsing_possible = False

    for run in procedure["runs"]:

        if any([i not in run for i in constants.PROCEDURE_RUN_FIELDS]):
            return False, "A specified run in strategy script " + run["strategy"] + " is missing required field(s)."

        if run["strategy"] not in strategy_map:
            return False, "The specified strategy script " + run["strategy"] + " is not found in this build."

        strat = strategy_map[run["strategy"]]

        run_found = False
        for r in strat["runs"]:
            if r["run_order"] == run["run_order"]:
                matched_run = r
                run_found = True

        if not run_found:
            return False, "The specified run in strategy " + run["strategy"] + " cannot be found."

        if len(run["user_params"]) != len(matched_run["user_params"]):
            return False, "Mismatching user parameters supplied in strategy " + run["strategy"] + "."

        for param in run["user_params"]:
            matching_params = [i for i in matched_run["user_params"] if i[0] == param[0] and type(param[1]) == i[1]]
            if len(matching_params) != 1:
                return False, "Incorrect specification of user parameter " + param + "."

        pt_collection_valid = False
        if mongo_reader.select(run["pt_collection"]):
            pt_collection_valid = True

        if pt_filters_validated:
            if Counter([i[1] for i in pt_filters]) != Counter(strat["pt_filters"]):
                return False, "Some PT input filters are not of a valid type, or not supplied with an invalid existing collection."

        if (not pt_collection_valid) and (not pt_reparsing_possible):
            return False, "Neither the supplied PT pcap file and filters, nor an existing PT collection is valid."

        # Skip validating negative inputs if not required by the strategy.
        if not strat["negative_input"]:
            continue

        neg_collection_valid = False
        if mongo_reader.select(run["neg_collection"]):
            neg_collection_valid = True

        if neg_filters_validated:
            if Counter([i[1] for i in neg_filters]) != Counter(strat["negative_filters"]):
                return False, "Some negative input filters are not of a valid type, or not supplied with an invalid existing collection."

        if not (neg_collection_valid or neg_reparsing_possible):
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

    val, msg = validate_procedure(procedure, strategy_map)
    if not val:
        print("The procedure failed to import due to: {}.".format(msg))
        return False

    return procedure


def execute_procedure(procedure, strategy_map):
    """
    Execute a validated procedure and preserve their strategy states in order.
    :param procedure: a dict containing a CovertMark procedure.
    :param strategy_map: a strategy map validated by covertmark.py.
    :returns: a list of tuples each containing a strategy instances executed
        based on runs specified in the procedure, and the run specification.
        Returns empty list if execution fails.
    """

    val, _ = validate_procedure(procedure, strategy_map)
    if not val:
        return []

    mongo_reader = data.retrieve.Retriever()
    completed_instances = []
    procedure_pt_filters = procedure["pt_filters"]
    procedure_pt_pcap = procedure["pt_pcap"]
    procedure_neg_filters = procedure["neg_filters"]
    procedure_neg_pcap = procedure["neg_pcap"]

    for run in procedure["runs"]:
        strat = strategy_map[run["strategy"]]
        strategy_module = getattr(strategy, strat["module"])
        strategy_object = getattr(strategy_module, strat["object"])
        use_negative = strat["negative_input"]
        run_info = [i for i in strat["runs"] if i["run_order"] == run["run_order"]][0]

        # Retrieve the IP filters.
        if mongo_reader.select(run["pt_collection"]):
            pt_filters = mongo_reader.get_input_filters()
            pt_use_collection = True
        else:
            pt_filters = procedure_pt_filters
            pt_use_collection = False

        if use_negative:
            if mongo_reader.select(run["neg_collection"]):
                negative_filters = mongo_reader.get_input_filters()
                negative_use_collection = True
            else:
                negative_filters = procedure_neg_filters
                negative_use_collection = False

        # Length and composition should have been validated in strategy map
        # reading, but for correctness asserted here.
        if not pt_use_collection:
            assert(len(pt_filters) == len(strat["pt_filters"]))
        if use_negative and not negative_use_collection:
            assert(len(negative_filters) == len(strat["negative_filters"]))

        # Map the filters.
        pt_filters_mapped = [[x[0], strategy.constants.FILTERS_REVERSE_MAP[x[1]]] for x in pt_filters]
        if use_negative:
            negative_filters_mapped = [[x[0], strategy.constants.FILTERS_REVERSE_MAP[x[1]]] for x in negative_filters]

        print("Attempting to execute " + strategy_object.NAME + " for " + run_info["run_description"] + "...\n")

        # Construct the parameters if applicable (PCAP path, input filters, existing collection)
        if pt_use_collection:
            pt_params = ["_", [], run["pt_collection"]]
        else:
            pt_filters_mapped = [tuple(i) for i in pt_filters_mapped] # Compability.
            pt_params = [os.path.expanduser(procedure_pt_pcap), pt_filters_mapped, None]

        if use_negative:
            if negative_use_collection:
                neg_params = ["_", [], run["neg_collection"]]
            else:
                negative_filters_mapped = [tuple(i) for i in negative_filters_mapped] # Compability.
                neg_params = [os.path.expanduser(procedure_neg_pcap), negative_filters_mapped, None]
        else:
            neg_params = [None, [], None]

        user_params = {i[0]: i[1] for i in run["user_params"]}

        try:
            strategy_instance = strategy_object(pt_params[0], neg_params[0])
            strategy_instance.setup(pt_ip_filters=pt_params[1],
                                    negative_ip_filters=neg_params[1],
                                    pt_collection=pt_params[2],
                                    negative_collection=neg_params[2])
            strategy_instance.run(**user_params)
        except Exception as e:
            print("Error: " + str(e))
            print("Exception was raised during the execution of this strategy, skipping...")
            continue

        print("Strategy run execution successful, saving the instance states.\n")
        completed_instances.append((strategy_instance, run))

    return completed_instances


def get_strategy_runs(strategy_map):
    """
    Return a pretty print tabulate for showing the user all available runs in
    all procedures.
    :param strategy_map: the strategy map to draw these information from.
    :returns: a tabulate.tabulate object containing these information.
    """

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

    return tabulate(available_runs, available_runs_header, tablefmt="fancy_grid")
