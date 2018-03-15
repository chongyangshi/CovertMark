import data.constants as data_constants

TPR_BOUNDARY = 0.333 # Below which results in ineffective detection.
FPR_BOUNDARY = 0.050 # Above which results in unacceptable false positives.
FPR_TARGET = 0.0025 # As FPR is of greater interest to censors, a hard rather than relative target will be used in scoring.
PENALTY_WEIGHTS = (0.25, 0.5, 0.25) # Penalisation weight between TPR, FPR, and positive run time.
assert(sum(PENALTY_WEIGHTS) == 1)

JSON_FILTERS = {
    'IP_SRC': data_constants.IP_SRC,
    'IP_DST': data_constants.IP_DST,
    'IP_EITHER': data_constants.IP_EITHER
}
JSON_OPT_PARAM_TYPES = {
    'int': int,
    'str': str,
    'bool': bool
}

STRATEGY_FIELDS = [("module", str), ("object", str), ("fixed_params", list),
    ("pt_filters", list), ("negative_filters", list), ("negative_input", bool),
    ("runs", list)]
RUN_FIELDS = [("run_order", int), ("run_description", str), ("pt_filters_reverse", bool),
 ("negative_filters_reverse", bool), ("user_params", list)]
FILTERS_REVERSE_MAP = {
    data_constants.IP_SRC: data_constants.IP_DST,
    data_constants.IP_DST: data_constants.IP_SRC,
    data_constants.IP_EITHER: data_constants.IP_EITHER
}
