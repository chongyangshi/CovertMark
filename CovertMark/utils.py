import os, sys
from json import load, dump
from importlib import import_module
import random, string
from operator import itemgetter
from collections import Counter
from tabulate import tabulate
from datetime import date
import hashlib

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

    if not procedure or len(procedure) == 0:
        return False, "The imported procedure is empty."

    for run in procedure:

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
            pt_filters = mongo_reader.get_input_filters()
            pt_collection_valid = True
        else:
            pt_filters = run["pt_filters"]
            if not all([data.utils.build_subnet(i[0]) for i in pt_filters]):
                return False, "PT input filters are not valid IP addresses or subnets."
            if set([i[1] for i in pt_filters]) != set(strat["pt_filters"]):
                return False, "Some PT input filters are not of a valid type, or not supplied with a valid existing collection."

        pt_pcap_valid = data.utils.check_file_exists(os.path.expanduser(run["pt_pcap"]))

        if not (pt_pcap_valid or pt_collection_valid):
            return False, "Neither the supplied PT pcap file and filters, nor an existing PT collection is valid."

        # Skip validating negative inputs if not required by the strategy.
        if not strat["negative_input"]:
            continue

        neg_collection_valid = False
        if mongo_reader.select(run["neg_collection"]):
            neg_filters = mongo_reader.get_input_filters()
            neg_collection_valid = True
        else:
            neg_filters = run["neg_filters"]
            if not all([data.utils.build_subnet(i[0]) for i in neg_filters]):
                return False, "negative input filters are not valid IP addresses or subnets."
            if set([i[1] for i in neg_filters]) != set(strat["negative_filters"]):
                return False, "Some negative input filters are not of a valid type, or not supplied with a valid existing collection."

        neg_pcap_valid = data.utils.check_file_exists(os.path.expanduser(run["neg_pcap"]))

        if not (neg_pcap_valid or neg_collection_valid):
            return False, "Neither the supplied negative pcap file and filters, nor an existing negative collection is valid."


    return True, "The procedure is successfully validated."


def save_procedure(export_path, procedure, strategy_map, overwrite=False):
    """
    Save a programmed CovertMark procedure into the path specified for later
    retrieval.
    :param export_path: a qualified system path for exporting the procedure.
    :param procedure: a procedure generated by covertmark.py.
    :param strategy_map: a strategy map validated by covertmark.py.
    :param overwrite: set to True to overwrite the target file if it exists.
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

    if not overwrite and data.utils.check_file_exists(export_path):
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

    val, msg = validate_procedure(procedure, strategy_map)
    if not val:
        print("The procedure failed to import due to: {}.".format(msg))
        return False

    return procedure


def execute_procedure(procedure, strategy_map, db_sub=False):
    """
    Execute a validated procedure and preserve their strategy states in order.
    :param procedure: a dict containing a CovertMark procedure.
    :param strategy_map: a strategy map validated by covertmark.py.
    :param db_sub: subsitute PCAP and input filters specified in the procedure
        with MongoDB-stored collection names, eliminating importing the same
        pcap file with same filters.
    :returns: a list of tuples each containing a strategy instances executed
        based on runs specified in the procedure, and the run specification.
        Returns empty list if execution fails. If `db_sub` is set, the updated
        procedure will also be returned as the second element of a tuple.
    """

    val, _ = validate_procedure(procedure, strategy_map)
    if not val:
        if db_sub:
            return [], procedure
        else:
            return []

    mongo_reader = data.retrieve.Retriever()
    completed_instances = []
    imported_pcaps = {}
    for run in procedure:
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
            pt_filters = run["pt_filters"]
            pt_key = format_pcap_filters(run["pt_pcap"], pt_filters, run_info["pt_filters_reverse"])
            if db_sub and pt_key in imported_pcaps:
                run["pt_collection"] = imported_pcaps[pt_key]
                pt_use_collection = True
            else:
                pt_use_collection = False

        if use_negative:
            if mongo_reader.select(run["neg_collection"]):
                negative_filters = mongo_reader.get_input_filters()
                negative_use_collection = True
            else:
                negative_filters = run["neg_filters"]
                negative_use_collection = False
                neg_key = format_pcap_filters(run["neg_pcap"], negative_filters, run_info["negative_filters_reverse"])
                if db_sub and pt_key in imported_pcaps:
                    run["neg_collection"] = imported_pcaps[neg_key]
                    negative_use_collection = True
                else:
                    negative_use_collection = False

        # Composition of filters should have been validated in strategy map
        # reading, but for correctness asserted here.
        if not pt_use_collection:
            assert(set([i[1] for i in pt_filters]) == set(strat["pt_filters"]))
        if use_negative and not negative_use_collection:
            assert(set([i[1] for i in negative_filters]) == set(strat["negative_filters"]))

        # Map the filters.
        if run_info["pt_filters_reverse"]:
            pt_filters = [[x[0], strategy.constants.FILTERS_REVERSE_MAP[x[1]]] for x in pt_filters]
        if use_negative and run_info["negative_filters_reverse"]:
            negative_filters = [[x[0], strategy.constants.FILTERS_REVERSE_MAP[x[1]]] for x in negative_filters]

        print("Attempting to execute " + strategy_object.NAME + " for " + run_info["run_description"] + "...\n")
        print("User defined name: " + run["user_defined_name"] + ".")

        # Construct the parameters if applicable (PCAP path, input filters, existing collection)
        if pt_use_collection:
            pt_params = ["_", [], run["pt_collection"]]
        else:
            pt_filters = [tuple(i) for i in pt_filters] # Compability.
            pt_params = [run["pt_pcap"], pt_filters, None]

        if use_negative:
            if negative_use_collection:
                neg_params = ["_", [], run["neg_collection"]]
            else:
                negative_filters = [tuple(i) for i in negative_filters] # Compability.
                neg_params = [run["neg_pcap"], negative_filters, None]
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

            # Record collection imported for possible reuse.
            if not pt_use_collection:
                pt_key = format_pcap_filters(run["pt_pcap"], pt_filters, run_info["pt_filters_reverse"])
                imported_pcaps[pt_key] = strategy_instance._pt_collection
                if db_sub:
                    run["pt_collection"] = strategy_instance._pt_collection
            if use_negative and (not negative_use_collection):
                neg_key = format_pcap_filters(run["neg_pcap"], negative_filters, run_info["negative_filters_reverse"])
                imported_pcaps[neg_key] = strategy_instance._neg_collection
                if db_sub:
                    run["neg_collection"] = strategy_instance._neg_collection

            # Light weight storage of states we actually need.
            strategy_instance.destroy_traces()
        except Exception as e:
            print(str(e))
            print("Exception was raised during the execution of this strategy, skipping...")
            continue

        print("Strategy run execution successful, saving the instance states.\n")
        completed_instances.append((strategy_instance, run))

    if db_sub:
        return completed_instances, procedure
    else:
        return completed_instances


def printable_procedure(procedure, strategy_map):
    """
    Provide a pretty-print tabulate of programmed strategy runs in the procedure.
    :param procedure: an imported CovertMark procedure.
    :param strategy_map: a strategy map validated by covertmark.py.
    :returns: a tabulate object containing the formatted procedure.
    """
    if len(procedure) == 0:
        return "The current procedure is empty."

    headers = ("Strategy", "Name", "PT Input", "Negative Input", "Runtime Parameters")
    runs = []
    for run in procedure:
        strategy_name = width(strategy_map[run["strategy"]]["object"], 15)
        run_name = width(run["user_defined_name"], 15)

        if run["pt_collection"] == "":
            pt_input = width(run["pt_pcap"], 25) + "\n"
            for f in run["pt_filters"]:
                if f[1] == data.constants.IP_SRC:
                    pt_input += "from    " + f[0] + '\n'
                elif f[1] == data.constants.IP_DST:
                    pt_input += "to      " + f[0] + '\n'
                else:
                    pt_input += "from/to " + f[0] + '\n'
        else:
            pt_input = "from MongoDB"

        if strategy_map[run["strategy"]]["negative_input"]:
            if run["neg_collection"] == "":
                neg_input = width(run["neg_pcap"], 25) + "\n"
                for f in run["neg_filters"]:
                    if f[1] == data.constants.IP_SRC:
                        neg_input += "from    " + f[0] + '\n'
                    elif f[1] == data.constants.IP_DST:
                        neg_input += "to      " + f[0] + '\n'
                    else:
                        neg_input += "from/to " + f[0] + '\n'
            else:
                neg_input = "from MongoDB"
        else:
            neg_input = "n/a"

        run_param = "\n".join([i[0] + ": " + str(i[1]) for i in run["user_params"]])

        runs.append((strategy_name, run_name, pt_input, neg_input, run_param))

    return tabulate(runs, headers, tablefmt="fancy_grid")


def get_strategy_runs(strategy_map):
    """
    Return a pretty print tabulate for showing the user all available runs in
    all procedures.
    :param strategy_map: the strategy map to draw these information from.
    :returns: a tuple containing a tabulate.tabulate object containing these
        information, and a list of tuples containing the strategy key and the
        run order specified for each row.
    """

    available_runs = [] # (selection_id, strategy_name, run_description)
    available_runs_header = ("Run ID", "Strategy Name", "Strategy Run Description")
    available_runs_indices = [] # (strategy_map_key, run_order)
    selection_id = 0
    for strategy_map_key, strat in strategy_map.items():
        strategy_class = getattr(getattr(strategy, strat["module"]), strat["object"])
        strategy_name = strategy_class.NAME
        for run in strat["runs"]:
            available_runs.append((selection_id, width(strategy_name, 30),
             width(run["run_description"], 30)))
            available_runs_indices.append((strategy_map_key, run["run_order"]))
            selection_id += 1

    return tabulate(available_runs, available_runs_header, tablefmt="fancy_grid"), available_runs_indices


def list_traces(traces):
    """
    Fetch stored traces in MongoDB for user selection.
    :param traces: a list of (un)filtered traces from data.retrieve.Retriever.list().
    :returns: tuple of a pretty-printable tabulate containing information of traces,
        and a dictionary mapping displayed IDs to the internal collection name.
    """

    header = ('ID', 'Description', 'Created', 'Stream Direction(s)', 'Packets')
    output = []
    collections = {}
    display_id = 0
    for trace in traces:
        description = width(trace['description'], 30)
        created = width(trace['creation_time'], 10)
        directions = ""
        trace_filters = sorted(trace["input_filters"], key=itemgetter(1))
        for f in trace["input_filters"]:
            if f[1] == data.constants.IP_SRC:
                directions += "from    " + f[0] + '\n'
            elif f[1] == data.constants.IP_DST:
                directions += "to      " + f[0] + '\n'
            else:
                directions += "from/to " + f[0] + '\n'
        size = trace['count']
        output.append((display_id, description, created, directions, size))
        collections[display_id] = trace['name']
        display_id += 1

    return tabulate(output, header, tablefmt="fancy_grid"), collections


def printable_results(results, strategy_map):
    """
    Provide a pretty-print tabulate of results.
    :param results: a dictionary of results from the handler indexed by a global
        handler counter, containing strategy modules, run orders, and result
        instances.
    :param strategy_map: a validated CovertMark strategy map.
    :returns: a tuple of a formatted tabulate of results.
    """

    headers = ("ID", "Strategy", "Run Description", "IPs", "Records")
    lines = []
    for c, result in results.items():
        strat = strategy_map[result[0]]
        instance = result[2]
        strategy_name = width(instance.NAME, 15)
        run_name = width(result[3], 20)
        ips = width(",".join([str(i) for i in instance._positive_subnets + instance._negative_subnets]), 25)
        records = len(instance._time_statistics)
        lines.append((c, strategy_name, run_name, ips, records))

    return tabulate(lines, headers, tablefmt="fancy_grid")


def width(text, width):
    """
    Insert a new line character for each block of `width` characters into the
    input text.
    :param text: the input text for newlining.
    :param width: a positive integer for dividing input with new lines.
    :returns: the newlined text.
    """

    if not isinstance(width, int) or width < 1:
        return text

    if not isinstance(text, str):
        return None

    text_segments = [text[i:i+width] for i in range(0, len(text), width)]

    return '\n'.join(text_segments)


def format_pcap_filters(pcap_path, input_filters, reverse):
    """
    Format the pcap path and its associated input filters into a dict key with
    consistent alphanumeric ordering for indexing same inputs to different
    strategy runs. Assumes path and input filters passed are all valid.
    :param pcap_path: the path to a pcap specified by a procedure run.
    :param input_filters: the associated input filters in the procedure run.
    :param reverse: whether the procedure run reversed the input filters from
        its original direction, affecting PCAP importing.
    :returns: a tuple containing the above information in a consistent ordering.
    """

    input_filters = sorted(input_filters, key=itemgetter(0, 1))
    if reverse:
        reversed_import = 1
    else:
        reversed_import = 0

    key = (pcap_path, reversed_import)
    for f in input_filters:
        key += (tuple(f),)

    return key


def random_file_name(prefix, extension):
    """
    Generate a random file name with fixed prefixes to be relatively collision-free.
    :param prefix: the fixed portion of the file name.
    :param extension: the filename extension of the file without dot.
    :returns: a valid UNIX file name containing the prefix and 8 random hexdigest
        characters.
    """

    today = date.today().strftime("%Y%m%d")

    return prefix + "_" + today + "_" + hashlib.sha1(os.urandom(8)).hexdigest()[:8] + "." + extension


def save_file(content, path):
    """
    Save string-formatted content to the file specified.
    :param content: string-formatted content to be written.
    :param path: a fully qualified path for the content to be written to.
    :returns: True if successfully written, False otherwise.
    """

    if not isinstance(content, str):
        return False

    # Check the export path is valid and writable.
    export_path = os.path.expanduser(path.strip())
    if data.utils.check_file_exists(export_path):
        return False

    if not check_write_permission(os.path.dirname(export_path)):
        return False

    try:
        with open(export_path, 'w') as export_file:
            export_file.write(content)
        return True
    except:
        return False


def save_csvs(results, out_path):
    """
    Save CSVs to a qualified path.
    :param results: a standard CovertMark results dictionary.
    :param out_path: a valid directory to export the CSVs.
    :return: a list of successfully written CSV full paths.
    """

    writes = {}
    for _, result in results.items():
        path = os.path.join(out_path, random_file_name(result[0] + "_" + str(result[1]), "csv"))
        writes[path] = result[2].make_csv()

    successful_paths = []
    for i in writes:
        if save_file(writes[i], i):
            successful_paths.append(i)

    return successful_paths
