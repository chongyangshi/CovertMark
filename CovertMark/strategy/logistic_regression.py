import analytics, data
from strategy.strategy import DetectionStrategy

import os
from sys import exit, argv
from datetime import date, datetime
from operator import itemgetter
from math import log1p, isnan
from random import randint
from collections import defaultdict
import numpy as np
from sklearn import preprocessing, model_selection, linear_model

class LRStrategy(DetectionStrategy):
    """
    A generic Logistic Regression-based strategy for observing patterns of traffic
    in both directions of stream. Not designed for identifying any particular
    existing PT, should allow a general use case based on traffic patterns.
    A single client IP should be used.
    """

    NAME = "Logistic Regression Strategy"
    DESCRIPTION = "Generic binary classification strategy."
    _MONGO_KEY = "lr" # Alphanumeric key for MongoDB.

    DEBUG = True
    WINDOW_SIZE = 200
    NUM_RUNS = 5
    OCCURANCE_THRESHOLD = 2


    def __init__(self, pt_pcap, negative_pcap=None):
        super().__init__(pt_pcap, negative_pcap, self.DEBUG)


    def set_strategic_filter(self):
        """
        LR only supports TCP-based PTs for now.
        """

        self._strategic_packet_filter = {"tcp_info": {"$ne": None}}


    def test_validation_split(self, split_ratio):
        """
        We call testing data used in training as test, and data used in negative
        run unseen during training as validaton.
        """

        if not isinstance(split_ratio, float) or not (0 <= split_ratio <= 1):
            raise ValueError("Invalid split ratio: {}".format(split_ratio))

        # Orde-preserving split of features, their labels, and their IPs.
        split = model_selection.train_test_split(self._strategic_states['all_features'],
         self._strategic_states['all_feature_labels'], self._strategic_states['all_ips'],
         train_size=split_ratio, shuffle=True)
        self._pt_test_labels = split[2]
        self._pt_validation_labels = split[3]
        self._pt_test_ips = split[4]
        self._pt_validation_ips = split[5]

        return (split[0], split[1])


    def positive_run(self, **kwargs):
        """
        Perform logistic regression on the training/testing dataset, and validate
        overfitting on validation dataset.
        :param run_num: the integer run number of this training/validation run.
        """

        run_num = 0 if not kwargs['run_num'] else kwargs['run_num']
        if not isinstance(run_num, int) or run_num < 0:
            raise ValueError("Incorrect run number.")

        self.debug_print("- Logistic Regression training {} with L1 penalisation and SAGA solver...".format(run_num+1))
        LR = linear_model.LogisticRegression(penalty='l1', dual=False,
         solver='saga', n_jobs=-1, max_iter=5000, warm_start=False)
        LR.fit(self._pt_test_traces, self._pt_test_labels)

        self.debug_print("- Logistic Regression validation...")
        prediction = LR.predict(self._pt_validation_traces)

        total_positives = 0
        true_positives = 0
        false_positives = 0
        total_negatives = 0
        true_negatives = 0
        false_negatives = 0
        self._strategic_states[run_num]["negative_blocked_ips"] = set([])
        self._strategic_states[run_num]["ip_occurances"] = defaultdict(int)
        for i in range(0, len(prediction)):
            ips_this_window = self._pt_validation_ips[i]

            if prediction[i] == 1:
                # The classifier believes that this window contains PT.
                # However we only block an IP and flag a window if the IP appears
                # in more than self.OCCURANCE_THRESHOLD windows seen so far.
                positive_decision = False
                for ip in ips_this_window:
                    self._strategic_states[run_num]["ip_occurances"][ip] += 1
                    if self._strategic_states[run_num]["ip_occurances"][ip] >= self.OCCURANCE_THRESHOLD:
                        # Threshold for this IP to be classified as PT is met.
                        positive_decision = True

                # Tally decision for the whole window.
                if positive_decision:
                    total_positives += 1
                else:
                    total_negatives += 1

                # Check how we did against the unseen label.
                if self._pt_validation_labels[i] == 1:
                    if positive_decision: # We were right to block here.
                        true_positives += 1
                    else: # We missed it this time, due to being conservative.
                        false_negatives += 1
                else:
                    if positive_decision: # False positive! We blocked an innocent IP.
                        false_positives += 1
                        for ip in ips_this_window: # Tally it.
                            self._strategic_states[run_num]["negative_blocked_ips"].add(ip)
                    else: # We were right to not block here.
                        true_negatives += 1

            else:
                total_negatives += 1
                if self._pt_validation_labels[i] == 0:
                    true_negatives += 1
                else:
                    false_negatives += 1

        self._strategic_states[run_num]["total"] = total_positives + total_negatives
        self._strategic_states[run_num]["TPR"] = float(true_positives) / total_positives
        self._strategic_states[run_num]["FPR"] = float(false_positives) / total_positives
        self._strategic_states[run_num]["TNR"] = float(true_negatives) / total_negatives
        self._strategic_states[run_num]["FNR"] = float(false_negatives) / total_negatives
        self._strategic_states[run_num]["false_positive_blocked_rate"] = \
         float(len(self._strategic_states[run_num]["negative_blocked_ips"])) / self._negative_unique_ips

        return self._strategic_states[run_num]["TPR"]


    def negative_run(self):
        """
        Not used at this time, as FPR combined into self.positive_run.
        """

        return None


    def report_blocked_ips(self):
        """
        Cannot distinguish directions in this case.
        """
        wireshark_output = "tcp && ("
        for i, ip in enumerate(list(self._negative_blocked_ips)):
            wireshark_output += "ip.dst_host == \"" + ip + "\" "
            if i < len(self._negative_blocked_ips) - 1:
                wireshark_output += "|| "
        wireshark_output += ")"

        return wireshark_output


    def run(self, pt_ip_filters=[], negative_ip_filters=[], pt_split=True,
     pt_split_ratio=0.5, pt_collection=None, negative_collection=None):
        """
        Overriding default run() to test over multiple block sizes and p-value
        thresholds.
        """

        self._run(pt_ip_filters, negative_ip_filters, pt_collection=pt_collection,
         negative_collection=negative_collection)

        self.debug_print("Loaded {} positive traces, {} negative traces.".format(len(self._pt_traces), len(self._neg_traces)))
        self.debug_print("- Applying windowing to the traces...")
        positive_windows = analytics.traffic.window_traces_fixed_size(self._pt_traces, self.WINDOW_SIZE)
        self._pt_traces = None # Give memory when processing large files.
        negative_windows = analytics.traffic.window_traces_fixed_size(self._neg_traces, self.WINDOW_SIZE)
        self._neg_traces = None

        self.debug_print("- Extracting features from windowed traffic...")
        if (not any([i[1] == data.constants.IP_EITHER for i in pt_ip_filters])) or \
            (not any([i[1] == data.constants.IP_EITHER for i in negative_ip_filters])):
            raise ValueError("This strategy requires a valid source+destination IP/subnet set for the input filters!")

        positive_features = []
        positive_ips = []
        for ip in pt_ip_filters:
            if ip[1] == data.constants.IP_EITHER:
                client_ip = ip[0]
                break
        self.debug_print("The suspected PT client(s) in positive cases are assumed as {}.".format(client_ip))
        for window in positive_windows:
            feature_dict, ips = analytics.traffic.get_window_stats(window, client_ip)
            if any([(not feature_dict[i]) or isnan(feature_dict[i]) for i in feature_dict]):
                continue
            positive_ips.append(ips)
            positive_features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])
        positive_windows = []

        negative_features = []
        negative_ips = []
        for ip in negative_ip_filters:
            if ip[1] == data.constants.IP_EITHER:
                client_ip = ip[0]
                break
        self.debug_print("The suspected PT client(s) in negative cases are assumed as {}.".format(client_ip))
        for window in negative_windows:
            feature_dict, ips = analytics.traffic.get_window_stats(window, client_ip)
            if any([(not feature_dict[i]) or isnan(feature_dict[i]) for i in feature_dict]):
                continue
            negative_ips.append(ips)
            negative_features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])
        negative_windows = []

        self.debug_print("Prepared {} positive windows, {} negative windows.".format(\
         len(positive_features), len(negative_features)))
        if len(positive_features) < 1 or len(negative_features) < 1:
            raise ValueError("No windows to work with, did you misconfigure the input filters?")
        all_features = positive_features + negative_features
        all_features = np.asarray(all_features, dtype=np.float64)
        all_labels = [1 for i in range(len(positive_features))] + [0 for i in range(len(negative_features))]
        all_labels = np.asarray(all_labels, dtype=np.int8)
        all_ips = positive_ips + negative_ips
        positive_features = []
        negative_features = [] # Explicit removal from memory.
        positive_ips = []
        negative_ips = []

        # Rescale to zero centered uniform variance data.
        self._strategic_states['all_features'] = preprocessing.scale(all_features,
         axis=0, copy=False)
        self._strategic_states['all_feature_labels'] = all_labels
        self._strategic_states['all_ips'] = all_ips
        all_features = []
        all_labels = []
        all_ips = []

        # Run training and validation for self.NUM_RUNS times.
        for i in range(self.NUM_RUNS):
            self.debug_print("LR Run {} of {}".format(i+1, self.NUM_RUNS))

            # Redraw the samples and resplit.
            self.debug_print("- Splitting training/validation by the ratio of {}.".format(pt_split_ratio))
            self._split_pt(pt_split_ratio)

            if not self._pt_split:
                self.debug_print("Training/validation case splitting failed, check data.")
                return False

            self._strategic_states[i] = {}
            self._run_on_positive(run_num=i)

            self.debug_print("Results of validation: ")
            self.debug_print("Total: {}".format(self._strategic_states[i]["total"]))
            self.debug_print("TPR: {:0.2f}%, TNR: {:0.2f}%".format(\
             self._strategic_states[i]['TPR']*100, self._strategic_states[i]['TNR']*100))
            self.debug_print("FPR: {:0.2f}%, FNR: {:0.2f}%".format(\
             self._strategic_states[i]['FPR']*100, self._strategic_states[i]['FNR']*100))
            self.debug_print("Falsely blocked {} ({:0.2f}%) of IPs in validation.".format(len(self._strategic_states[i]["negative_blocked_ips"]), self._strategic_states[i]["false_positive_blocked_rate"]*100))

        # As LR is relatively stable, we only need to pick the lowest FPR and
        # do not need to worry about too low a corresponding TPR.
        fpr_results = [self._strategic_states[i]['FPR'] for i in range(self.NUM_RUNS)]
        best_fpr_run = min(enumerate(fpr_results), key=itemgetter(1))[0]

        # Best result processing:
        self._true_positive_rate = self._strategic_states[best_fpr_run]['TPR']
        self._false_positive_rate = self._strategic_states[best_fpr_run]['FPR']
        self._negative_blocked_ips = self._strategic_states[best_fpr_run]["negative_blocked_ips"]
        self._false_positive_blocked_rate = self._strategic_states[best_fpr_run]["false_positive_blocked_rate"]
        self.debug_print("Best: TPR {:0.2f}%, FPR {:0.2f}%, blocked {} ({:0.2f}%)".format(\
         self._true_positive_rate*100, self._false_positive_rate*100,
         len(self._negative_blocked_ips), self._false_positive_blocked_rate*100))
        ips = str(sorted(self._strategic_states[best_fpr_run]["ip_occurances"].items(), key=itemgetter(1)))
        self.debug_print("Appearances of IPs in classifier's positvie windows in this run (actually blocked at >= {} occurances): {}".format(self.OCCURANCE_THRESHOLD, ips))

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # Short test.
    # lr_path = os.path.join(parent_path, 'examples', 'meek.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'unobfuscated.pcap')
    # detector = LRStrategy(lr_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('172.28.192.0/24', data.constants.IP_EITHER)],
    #     negative_ip_filters=[('172.28.192.0/24', data.constants.IP_EITHER)])
    # detector.clean_up_mongo()
    # print(detector.report_blocked_ips())
    # exit(0)

    # Longer ACS Test.
    # lr_path = os.path.join(parent_path, 'examples', 'local', 'meeklong.pcap')
    # unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'cantab.pcap')
    # detector = LRStrategy(lr_path, unobfuscated_path)
    # detector.run(pt_ip_filters=[('192.168.0.42', data.constants.IP_EITHER)],
    #     negative_ip_filters=[('128.232.17.0/24', data.constants.IP_EITHER)],
    #     pt_collection="traces20180217bedd6553b1ad347c547c6440db8625a30124958b",
    #     negative_collection="traces201802179204e6b362c82a2e90f71e261570f36a69ff064e")

    lr_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', argv[2])
    detector = LRStrategy(lr_path, unobfuscated_path)
    detector.run(pt_ip_filters=[(argv[3], data.constants.IP_EITHER)],
     negative_ip_filters=[(argv[4], data.constants.IP_EITHER)],
     pt_collection=argv[5], negative_collection=argv[6])
    print(detector.report_blocked_ips())
