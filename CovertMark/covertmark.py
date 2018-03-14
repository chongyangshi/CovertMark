import os, sys
from json import load

import data.utils as data_utils
import strategy.constants as strategy_constants

# Read the strategy map.
strategy_map = os.path.join(os.path.dirname(os.path.realpath(__file__)), "strategy", "strategy_map.json")
if not data_utils.check_file_exists(strategy_map):
    print("No strategy map: strategy/strategy_map.json does not exist, exiting.")
    sys.exit(1)

try:
    strategies = load(open(strategy_map, 'r'))
except:
    print("Invalid strategy map: strategy/strategy_map.json is invalid, exiting.")
    sys.exit(1)

if len(strategies) == 0:
    print("No strategy in strategy map: strategy/strategy_map.json, exiting.")
    sys.exit(1)

# Process the strategy map.
good_json = True
for strategy in strategies.values():

    for c, t in strategy_constants.STRATEGY_FIELDS:
        if c not in strategy or not isinstance(strategy[c], t):
            good_json = False

    pt_filters_len = len(strategy["pt_filters"])
    neg_filters_len = len(strategy["negative_filters"])

    # These are the parameters always applied to the strategy.run(..) call.
    for i in strategy["fixed_params"]:
        if len(i) != 2 or not i[0].isidentifier():
            good_json = False

    # Check defined filters:
    for i, w in enumerate(strategy["pt_filters"]):
        if w in strategy_constants.JSON_FILTERS:
            strategy["pt_filters"][i] = strategy_constants.JSON_FILTERS[w]
        else:
            good_json = False

    for i, w in enumerate(strategy["negative_filters"]):
        if w in strategy_constants.JSON_FILTERS:
            strategy["negative_filters"][i] = strategy_constants.JSON_FILTERS[w]
        else:
            good_json = False

    for r in strategy["runs"]:

        for c, t in strategy_constants.RUN_FIELDS:
            if c not in r or not isinstance(r[c], t):
                good_json = False

        for i, w in enumerate(r["pt_filters_map"]):
            if w in strategy_constants.JSON_FILTERS:
                r["pt_filters_map"][i] = strategy_constants.JSON_FILTERS[w]
            else:
                good_json = False

        if len(r["pt_filters_map"]) != pt_filters_len:
            good_json = False

        for i, w in enumerate(r["negative_filters_map"]):
            if w in strategy_constants.JSON_FILTERS:
                r["negative_filters_map"][i] = strategy_constants.JSON_FILTERS[w]
            else:
                good_json = False

        if len(r["negative_filters_map"]) != neg_filters_len:
            good_json = False

        # These are the parameters applied to the strategy.run(..) call with
        # only expected int/str/bool type defined, requiring the user to
        # supply before the start of the runs.
        for i, w in enumerate(r["user_params"]):
            if len(w) != 2:
                good_json = False
            elif not w[0].isidentifier() or w[1] not in strategy_constants.JSON_OPT_PARAM_TYPES:
                good_json = False
            else:
                r["user_params"][i] = [w[0], strategy_constants.JSON_OPT_PARAM_TYPES[w[1]]]


if not good_json:
    print("Invalid json in strategy map: strategy/strategy_map.json, exiting.")
    sys.exit(1)
