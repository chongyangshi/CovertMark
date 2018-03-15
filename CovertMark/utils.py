import os
from json import load
from importlib import import_module

import data, strategy

def read_strategy_map():
    """
    Read in the strategy map from strategy/strategy_map.json.
    :returns: (succ, msg), succ = True if valid strategy map, False otherwise,
        with msg containing the error found.
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

    return True, "Successfully parsed strategy/strategy_map.json."
