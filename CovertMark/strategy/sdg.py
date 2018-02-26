import analytics, data
from strategy.logistic_regression import LRStrategy

import os
from sys import exit, argv
from datetime import date, datetime
from operator import itemgetter
from math import log1p, isnan, floor
from random import randint
from collections import defaultdict
import numpy as np
from sklearn import preprocessing, model_selection, linear_model

class SDGStrategy(LRStrategy):
    """
    A generic SDG-based strategy for observing patterns of traffic in both
    directions of stream. Not designed for identifying any particular
    existing PT, should allow a general use case based on traffic patterns.
    Should achieve better unseen recall performance than Logistic Regression.
    A single client IP should be used.
    """

    NAME = "SDG Strategy"
    DESCRIPTION = "Generic binary classification strategy."
    _MONGO_KEY = "lr" # Currently sharing MongoDB storage due to no change in preprocessing.
    _DEBUG_PREFIX = "sdg"

    LOSS_FUNC = "hinge"
    DEBUG = True
    WINDOW_SIZE = 50
    TIME_SEGMENT_SIZE = 60
    NUM_RUNS = 5
    DYNAMIC_THRESHOLD_PERCENTILES = [0, 50, 75, 80, 85, 90]
    DYNAMIC_ADJUSTMENT_STOPPING_CRITERIA = (0.75, 0.001)
    # Stop when TPR drops below first value or FPR drops below second value.

    def __init__(self, pt_pcap, negative_pcap=None, recall_pcap=None):
        super().__init__(pt_pcap, negative_pcap, recall_pcap)
        self._trained_classifiers = {}


    def positive_run(self, **kwargs):
        """
        Perform SDG learning on the training/testing dataset, and validate
        overfitting on validation dataset.
        :param run_num: the integer run number of this training/validation run.
        """

        run_num = 0 if not kwargs['run_num'] else kwargs['run_num']
        if not isinstance(run_num, int) or run_num < 0:
            raise ValueError("Incorrect run number.")

        self.debug_print("- SDG training {} with L1 penalisation and {} loss...".format(run_num+1, self.LOSS_FUNC))
        SDG = analytics.learning.SDG(loss=self.LOSS_FUNC, multithreaded=True)
        SDG.train(self._pt_test_traces, self._pt_test_labels)

        self.debug_print("- SDG validation...")
        prediction = SDG.predict(self._pt_validation_traces)

        total_positives = 0
        true_positives = 0
        false_positives = 0
        total_negatives = 0
        true_negatives = 0
        false_negatives = 0
        self._strategic_states[run_num]["negative_blocked_ips"] = set([])
        self._strategic_states[run_num]["ip_occurrences"] = defaultdict(int)
        for i in range(0, len(prediction)):
            target_ip_this_window = self._pt_validation_ips[i]

            if prediction[i] == 1:
                self._strategic_states[run_num]["ip_occurrences"][target_ip_this_window] += 1

                # Threshold check.
                if self._strategic_states[run_num]["ip_occurrences"][target_ip_this_window] > self._decision_threshold:
                    decide_to_block = True
                else:
                    decide_to_block = False

                if self._pt_validation_labels[i] == 1: # Actually PT traffic.
                    if decide_to_block: # We were right.
                        true_positives += 1
                    else: # Being conservative in blocking caused us to miss it.
                        false_negatives += 1
                else: # Actually non-PT traffic.
                    if decide_to_block: # We got it wrong.
                        self._strategic_states[run_num]["negative_blocked_ips"].add(self._pt_validation_ips[i])
                        false_positives += 1
                    else: # It was right to be conservative for this IP.
                        true_negatives += 1

            else:
                if self._pt_validation_labels[i] == 0:
                    true_negatives += 1
                else:
                    false_negatives += 1

        self._strategic_states[run_num]["total"] = true_positives + false_positives + true_negatives + false_negatives
        self._strategic_states[run_num]["TPR"] = float(true_positives) / (true_positives + false_negatives)
        self._strategic_states[run_num]["FPR"] = float(false_positives) / (false_positives + true_negatives)
        self._strategic_states[run_num]["TNR"] = float(true_negatives) / (true_negatives + false_positives)
        self._strategic_states[run_num]["FNR"] = float(false_negatives) / (false_negatives + true_positives)
        self._strategic_states[run_num]["false_positive_blocked_rate"] = \
         float(len(self._strategic_states[run_num]["negative_blocked_ips"])) / \
         self._strategic_states['negative_unique_ips']
        self._strategic_states[run_num]["classifier"] = SDG

        return self._strategic_states[run_num]["TPR"]


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # Shorter test.
    # mixed_path = os.path.join(parent_path, 'examples', 'local', 'meeklong_unobfuscatedlong_merge.pcap')
    # detector = SDGStrategy(mixed_path)
    # detector.run(pt_ip_filters=[('192.168.0.42', data.constants.IP_EITHER)],
    #     negative_ip_filters=[('172.28.195.198', data.constants.IP_EITHER)])
    # detector.clean_up_mongo()
    # print(detector.report_blocked_ips())
    # exit(0)

    mixed_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    recall_path = os.path.join(parent_path, 'examples', 'local', argv[5])
    detector = SDGStrategy(mixed_path, recall_pcap=recall_path)
    detector.run(pt_ip_filters=[(argv[2], data.constants.IP_EITHER)],
     negative_ip_filters=[(argv[3], data.constants.IP_EITHER)],
     pt_collection=argv[4], negative_collection=None, test_recall=True,
     recall_ip_filters=[(argv[6], data.constants.IP_EITHER)],
     recall_collection=argv[7])
    print(detector.report_blocked_ips())
