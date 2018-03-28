from .. import analytics, data
from .strategy import DetectionStrategy

import os
from sys import exit, argv
from datetime import date, datetime
from operator import itemgetter
from math import log1p, isnan, floor
from random import randint
from collections import defaultdict
import numpy as np
from sklearn import preprocessing, model_selection, linear_model
import sklearn.utils as sklearn_utils

class SDGStrategy(DetectionStrategy):
    """
    A generic SDG-based strategy for observing patterns of traffic in both
    directions of stream. Not designed for identifying any particular
    existing PT, should allow a general use case based on traffic patterns.
    It should achieve better unseen recall performance than Logistic Regression.
    """

    NAME = "SDG Classifier Strategy"
    DESCRIPTION = "Generic binary classification strategy."
    _DEBUG_PREFIX = "sdg"
    RUN_CONFIG_DESCRIPTION = ("Occurrence Threshold (%ile)", "Run #")

    LOSS_FUNC = "hinge"
    TIME_SEGMENT_SIZE = 60
    NUM_RUNS = 5
    FEATURE_SET = [analytics.constants.USE_ENTROPY, analytics.constants.USE_PSH,
                   analytics.constants.USE_INTERVAL_BINS,
                   analytics.constants.USE_TCP_LEN_BINS]
    DYNAMIC_THRESHOLD_PERCENTILES = [0, 50, 75, 80, 85, 90]
    DYNAMIC_ADJUSTMENT_STOPPING_CRITERIA = (0.75, 0.001)
    PT_SPLIT_RATIO = 0.5
    # Stop when TPR drops below first value or FPR drops below second value.

    def __init__(self, pt_pcap, negative_pcap, recall_pcap=None, debug=True):
        super().__init__(pt_pcap, negative_pcap, recall_pcap, debug=debug)
        self._trained_classifiers = {}


    def set_strategic_filter(self):
        """
        Only supports TCP-based PTs for now due to SEQ-related shaping.
        """

        self._strategic_packet_filter = {"tcp_info": {"$ne": None}}


    def interpret_config(self, config_set):
        """
        Threshold percentile and run # are used to distinguish SDG runs.
        """

        if config_set is not None:
            return "Run #{} of Occurrence Threshold at {}%ile.".format(config_set[1]+1, config_set[0])
        else:
            return ""


    def config_specific_penalisation(self, config_set):
        """
        The lower the occurrence threshold is, the easier it is to perform
        live classification. Therefore, a 5% penalty is applied for every 20%
        of occurrence threshold raised.
        """

        if isinstance(config_set, tuple) and len(config_set) >= 1 and \
         isinstance(config_set[0], int) and  0 <= config_set[0] <= 100:
            return 0.25 * (float(config_set[0]) / 100)


    def test_validation_split(self, split_ratio):
        """
        Split the inputs into test and validation traces through random sampling
        over all feature rows.
        We refer to testing data used in training as test, and data used in negative
        run unseen during training as validaton. It is important to balance the
        positive and negative sample counts, as over-supply of negative cases
        can severely damage the recall performance on unseen inputs captured
        separately.
        """

        if not isinstance(split_ratio, float) or not (0 <= split_ratio <= 1):
            raise ValueError("Invalid split ratio: {}".format(split_ratio))

        # Make sure that we do not train with too many negative cases, causing
        # significant overfitting in practice.
        positive_len = len(self._strategic_states['positive_features'])
        negative_len = len(self._strategic_states['negative_features'])
        if positive_len >= negative_len:
            self.debug_print("More positive than negative cases provided, drawing {} positive cases, {} negative cases.".format(positive_len, negative_len))
            negative_features, negative_ips = self._strategic_states['negative_features'], self._strategic_states['negative_ips']
        else:
            self.debug_print("More negative than positive cases provided, drawing {} positive cases, {} negative cases.".format(positive_len, positive_len))
            negative_features, negative_ips = sklearn_utils.resample(self._strategic_states['negative_features'], self._strategic_states['negative_ips'], replace=False, n_samples=positive_len)
            negative_len = positive_len

        # Reassemble the inputs.
        all_features = np.concatenate((self._strategic_states['positive_features'], negative_features), axis=0)
        all_ips = self._strategic_states['positive_ips'] + negative_ips
        all_labels = [1 for i in range(positive_len)] + [0 for i in range(negative_len)]
        self._strategic_states['negative_unique_ips'] = len(set(negative_ips))
        for ip in all_ips:
            self._target_ip_occurrences[ip] += 1

        # Rescale to zero centered uniform variance data.
        all_features = preprocessing.scale(all_features, axis=0, copy=False)

        # Orde-preserving split of features, their labels, and their IPs.
        split = model_selection.train_test_split(all_features, all_labels, all_ips,
         train_size=split_ratio, shuffle=True)

        self._pt_test_labels = split[2]
        self._pt_validation_labels = split[3]
        self._pt_test_ips = split[4]
        self._pt_validation_ips = split[5]

        return (split[0], split[1])


    def positive_run(self, **kwargs):
        """
        Perform SDG learning on the training/testing dataset, and validate
        overfitting on validation dataset.

        :param int threshold_pct: the occurrence threshold %ile used to tolerate
            low number of classifier positive hits to reduce false positives.
        :param int run_num: the integer run number of this training/validation run.
        """

        threshold_pct = 0 if 'threshold_pct' not in kwargs else kwargs['threshold_pct']
        run_num = 0 if 'run_num' not in kwargs else kwargs['run_num']
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
                    else: # It was right to be conservative about this IP.
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

        # Manual update of performance stats due to combined runs.
        # self.run_on_positive will set TPR to the same value again, but it is
        # fine.
        self.register_performance_stats(config=(threshold_pct, run_num),
                                   TPR=self._strategic_states[run_num]["TPR"],
                                   FPR=self._strategic_states[run_num]["FPR"],
                                   ip_block_rate=self._strategic_states[run_num]["false_positive_blocked_rate"])

        return self._strategic_states[run_num]["TPR"]


    def negative_run(self):
        """
        Not used at this time, as FPR combined into :meth:`positive_run`.
        """

        return None


    def recall_run(self, **kwargs):
        """
        Run the classifier with lowest FPR at each occurrence threshold on
        unseen recall traces.
        """

        self.debug_print("- Recall test started, extracting features from recall traces...")
        time_windows = analytics.traffic.window_traces_time_series(self._recall_traces, self.TIME_SEGMENT_SIZE*1000000, sort=False)

        # Process the all-positive recall windows.
        recall_features = []
        for time_window in time_windows:
            traces_by_client = analytics.traffic.group_traces_by_ip_fixed_size(time_window, self._recall_subnets, self._window_size)

            for client_target in traces_by_client:
                for window in traces_by_client[client_target]:
                    feature_dict, _, _ = analytics.traffic.get_window_stats(window, [client_target[0]], self.FEATURE_SET)
                    if any([(feature_dict[i] is None) or isnan(feature_dict[i]) for i in feature_dict]):
                        continue
                    recall_features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])

        # Test them on the best classifiers.
        total_recalls = len(recall_features)
        recall_accuracies = []
        for n, classifier in enumerate(self._trained_classifiers):
            self.debug_print("- Testing classifier #{} recall on {} feature rows...".format(n+1, total_recalls))

            correct_recalls = 0
            recall_predictions = classifier.predict(recall_features)
            for prediction in recall_predictions:
                if prediction == 1:
                    correct_recalls += 1

            recall_accuracies.append(float(correct_recalls)/total_recalls)
            self.debug_print("Classifier #{} recall accuracy: {:0.2f}%".format(n+1, float(correct_recalls)/total_recalls*100))

        return max(recall_accuracies)


    def report_blocked_ips(self):
        """
        We cannot distinguish directions in this strategy.
        """

        wireshark_output = "tcp && ("
        for i, ip in enumerate(list(self._negative_blocked_ips)):
            wireshark_output += "ip.dst_host == \"" + ip + "\" "
            if i < len(self._negative_blocked_ips) - 1:
                wireshark_output += "|| "
        wireshark_output += ")"

        return wireshark_output


    def run_strategy(self, **kwargs):
        """
        Input traces are assumed to be chronologically ordered, misfunctioning
        otherwise.
        Sacrificing some false negatives for low false positive rate, under
        dynamic occurrence thresholding.

        :param int window_size: the number of traces in each segment of single
            client-remote TCP sessions.
        :param int decision_threshold: leave as None for automatic decision threshold
            search, otherwise the number of IP occurrences before positive flagging.
        """

        window_size = 50 if 'window_size' not in kwargs else kwargs['window_size']
        if not isinstance(window_size, int) or window_size < 10:
            raise ValueError("Invalid window_size.")
        self._window_size = window_size
        self.debug_print("Setting window size at {}.".format(self._window_size))

        # Threshold at which to decide to block IP in validation, dynamic
        # adjustment based on percentile of remote host occurrences if unset.
        dynamic_adjustment = True
        decision_threshold = None if 'decision_threshold' not in kwargs else kwargs['decision_threshold']
        if decision_threshold is not None and isinstance(decision_threshold, int):
            self._decision_threshold = decision_threshold
            self.debug_print("Manually setting {} as the threshold at which to decide to block IP in validation.".format(self._decision_threshold))
            dynamic_adjustment = False

        test_recall = False if 'test_recall' not in kwargs else kwargs['test_recall']
        self.debug_print("Loaded {} positive traces, {} negative traces.".format(len(self._pt_traces), len(self._neg_traces)))
        if test_recall:
            self.debug_print("Loaded {} positive recall traces".format(len(self._recall_traces)))

        if len(self._pt_traces) < 1 or len(self._neg_traces) < 1:
            raise ValueError("Loaded nothing for at least one set of traces, did you set the input filter correctly?")

        # Synhronise times, moving the shorter one to reduce memory footprint.
        if len(self._pt_traces) > len(self._neg_traces):
            target_time = float(self._pt_traces[0]['time'])
            self._neg_traces = analytics.traffic.synchronise_traces(self._neg_traces, target_time, sort=False)
        else:
            target_time = float(self._neg_traces[0]['time'])
            self._pt_traces = analytics.traffic.synchronise_traces(self._pt_traces, target_time, sort=False)

        self.debug_print("- Segmenting traces into {} second windows...".format(self.TIME_SEGMENT_SIZE))
        time_windows_positive = analytics.traffic.window_traces_time_series(self._pt_traces, self.TIME_SEGMENT_SIZE*1000000, sort=False)
        time_windows_negative = analytics.traffic.window_traces_time_series(self._neg_traces, self.TIME_SEGMENT_SIZE*1000000, sort=False)
        self._pt_traces = None # Releases memory when processing large files.
        self._neg_traces = None
        self.debug_print("In total we have {} time segments.".format(len(time_windows_positive) + len(time_windows_negative)))

        self.debug_print("- Extracting feature rows from windows in time segments...")
        positive_features = []
        negative_features = []
        positive_ips = []
        negative_ips = []

        for time_window in time_windows_positive:
            traces_by_client = analytics.traffic.group_traces_by_ip_fixed_size(time_window, self._positive_subnets, self._window_size)

            for client_target in traces_by_client:

                # Mark the shared target.
                window_ip = client_target[1]
                for window in traces_by_client[client_target]:
                    # Extract features, IP information not needed as each window will
                    # contain one individual client's traffic with a single target only.
                    feature_dict, _, _ = analytics.traffic.get_window_stats(window, [client_target[0]], self.FEATURE_SET)
                    if any([(feature_dict[i] is None) or isnan(feature_dict[i]) for i in feature_dict]):
                        continue

                    # Commit this window if the features came back fine.
                    positive_features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])
                    positive_ips.append(window_ip)

        for time_window in time_windows_negative:
            traces_by_client = analytics.traffic.group_traces_by_ip_fixed_size(time_window, self._negative_subnets, self._window_size)

            for client_target in traces_by_client:

                # Mark the shared target.
                window_ip = client_target[1]
                for window in traces_by_client[client_target]:
                    # Extract features, IP information not needed as each window will
                    # contain one individual client's traffic with a single target only.
                    feature_dict, _, _ = analytics.traffic.get_window_stats(window, [client_target[0]], self.FEATURE_SET)
                    if any([(feature_dict[i] is None) or isnan(feature_dict[i]) for i in feature_dict]):
                        continue

                    # Commit this window if the features came back fine.
                    negative_features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])
                    negative_ips.append(window_ip)

        time_windows_positive = []
        time_windows_negative = []
        traces_by_client = []

        self.debug_print("Extracted {} rows representing windows containing PT traces, {} rows representing negative traces.".format(len(positive_features), len(negative_features)))
        if len(positive_features) < 1 or len(negative_features) < 1:
            raise ValueError("No feature rows to work with, did you misconfigure the input filters?")

        self._strategic_states['positive_features'] = np.asarray(positive_features, dtype=np.float64)
        self._strategic_states['negative_features'] = np.asarray(negative_features, dtype=np.float64)
        self._strategic_states['positive_ips'] = positive_ips
        self._strategic_states['negative_ips'] = negative_ips
        positive_features = []
        negative_features = []
        positive_ips = []
        negative_ips = []

        # Perform dynamic adjustment if set, otherwise finish after 1 loop.
        for threshold_pct in self.DYNAMIC_THRESHOLD_PERCENTILES:

            if not dynamic_adjustment:
                threshold_pct = decision_threshold

            self.debug_print("- Testing with threshold set at {} percentile...".format(threshold_pct))

            # Run training and validation for self.NUM_RUNS times.
            for i in range(self.NUM_RUNS):
                self.debug_print("{}pct LR Run {} of {}:".format(threshold_pct, i+1, self.NUM_RUNS))

                # Redraw the samples and resplit.
                self.debug_print("- Splitting training/validation by the ratio of {}.".format(self.PT_SPLIT_RATIO))
                self.split_pt(self.PT_SPLIT_RATIO)

                if not self._pt_split:
                    self.debug_print("Training/validation case splitting failed, check data.")
                    return False

                self._decision_threshold = floor(np.percentile(list(self._target_ip_occurrences.values()), threshold_pct))

                self._strategic_states[i] = {}
                self.run_on_positive((threshold_pct, i), run_num=i, threshold_pct=threshold_pct)

                self.debug_print("Results of {}pct validation run #{}: ".format(threshold_pct, i+1))
                self.debug_print("Total: {}".format(self._strategic_states[i]["total"]))
                self.debug_print("TPR: {:0.2f}%, TNR: {:0.2f}%".format(\
                 self._strategic_states[i]['TPR']*100, self._strategic_states[i]['TNR']*100))
                self.debug_print("FPR: {:0.2f}%, FNR: {:0.2f}%".format(\
                 self._strategic_states[i]['FPR']*100, self._strategic_states[i]['FNR']*100))
                self.debug_print("Falsely blocked {} ({:0.2f}%) of IPs in validation.".format(\
                 len(self._strategic_states[i]["negative_blocked_ips"]),
                 self._strategic_states[i]["false_positive_blocked_rate"]*100))

            # Pick the median false positive performance to decide whether to stop.
            fpr_results = [self._strategic_states[i]['FPR'] for i in range(self.NUM_RUNS)]
            median_fpr = sorted(fpr_results)[int(len(fpr_results)/2)]
            median_fpr_run = fpr_results.index(median_fpr)

            # Best result processing:
            self._true_positive_rate = self._strategic_states[median_fpr_run]["TPR"]
            self._false_positive_rate = self._strategic_states[median_fpr_run]["FPR"]
            self._negative_blocked_ips = self._strategic_states[median_fpr_run]["negative_blocked_ips"]
            self._false_positive_blocked_rate = self._strategic_states[median_fpr_run]["false_positive_blocked_rate"]
            self.debug_print("FPR Median: TPR {:0.2f}%, FPR {:0.2f}%, blocked {} ({:0.2f}%)".format(\
             self._true_positive_rate*100, self._false_positive_rate*100,
             len(self._negative_blocked_ips), self._false_positive_blocked_rate*100))
            self.debug_print("Occurrence threshold: {}%".format(threshold_pct))
            self.debug_print("IPs classified as PT (block at >{} occurrences):".format(self._decision_threshold))
            self.debug_print(', '.join([str(i) for i in sorted(list(self._strategic_states[median_fpr_run]["ip_occurrences"].items()), key=itemgetter(1), reverse=True)]))

            # Currently record first tier classifiers only.
            if threshold_pct == self.DYNAMIC_THRESHOLD_PERCENTILES[0]:
                self._trained_classifiers = [self._strategic_states[i]["classifier"] for i in range(self.NUM_RUNS)]

            if not dynamic_adjustment:
                break

            if self._strategic_states[median_fpr_run]['TPR'] < self.DYNAMIC_ADJUSTMENT_STOPPING_CRITERIA[0]:
                self.debug_print("Dynamic adjustment stops due to true positive rate dropping below criterion ({}).".format(self.DYNAMIC_ADJUSTMENT_STOPPING_CRITERIA[0]))
                break
            elif self._strategic_states[median_fpr_run]['FPR'] < self.DYNAMIC_ADJUSTMENT_STOPPING_CRITERIA[1]:
                self.debug_print("Dynamic adjustment stops due to false positive rate sufficiently low, criterion ({}).".format(self.DYNAMIC_ADJUSTMENT_STOPPING_CRITERIA[1]))
                break
            elif threshold_pct == self.DYNAMIC_THRESHOLD_PERCENTILES[-1]:
                self.debug_print("Dynamic adjustment stops at maximum threshold ({} pct)".format(threshold_pct))
                break

            for i in range(self.NUM_RUNS):
                self._strategic_states[i] = {}

        # Run recall test if required.
        self._strategic_states = {}

        if test_recall:
            self.debug_print("Running recall test as requested now.")
            self.run_on_recall()

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    pt_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    neg_path = os.path.join(parent_path, 'examples', 'local', argv[4])
    recall_path = os.path.join(parent_path, 'examples', 'local', argv[7])
    detector = SDGStrategy(pt_path, neg_path, recall_pcap=recall_path, debug=True)
    detector.setup(pt_ip_filters=[(i, data.constants.IP_EITHER) for i in argv[2].split(",")],
     negative_ip_filters=[(i, data.constants.IP_EITHER) for i in argv[5].split(",")],
     pt_collection=argv[3], negative_collection=argv[6], test_recall=True,
     recall_ip_filters=[(i, data.constants.IP_EITHER) for i in argv[8].split(",")],
     recall_collection=argv[9])
    detector.run(window_size=int(argv[10]), test_recall=True)
    print(detector.make_csv())
    score, best_config = detector._score_performance_stats()
    print("Score: {}, best config: {}.".format(score, detector.interpret_config(best_config)))
