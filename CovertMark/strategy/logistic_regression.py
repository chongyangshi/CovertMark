import analytics, data
from strategy.strategy import DetectionStrategy

import os
from sys import exit, argv
from datetime import date, datetime
from operator import itemgetter
from math import log1p, isnan, floor
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
    WINDOW_SIZE = 25
    TIME_SEGMENT_SIZE = 60
    NUM_RUNS = 5
    DYNAMIC_THRESHOLD_PERCENTILE = 75

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

                if decide_to_block: # Block it this time.
                    total_positives += 1
                else: # Not blocking it this time.
                    total_negatives += 1

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
         float(len(self._strategic_states[run_num]["negative_blocked_ips"])) / \
         self._strategic_states['negative_unique_ips']

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
     pt_split_ratio=0.5, pt_collection=None, negative_collection=None,
     decision_threshold=None):
        """
        This method requires positive-negative mixed pcaps with start time synchronised.
        Set pt_ip_filters and negative_ip_filters as usual, but they are also used
        to distinguish true and false positive cases in this strategy. Only
        pt_collection is used for the mixed pcap.
        Input traces are assumed to be chronologically ordered, misfunctioning
        otherwise.
        Sacrificing some false negatives for low false positive rate, under
        dynamic occurrence decision thresholding.
        """

        if pt_ip_filters == negative_ip_filters:
            raise ValueError("Mix PCAP in use, you need to be more specific about what IPs are PT clients in input filters.")

        # Merge the filters to path all applicable traffic in the mixed pcap.
        merged_filters = pt_ip_filters + negative_ip_filters
        client_ips = [ip[0] for ip in merged_filters if ip[1] == data.constants.IP_EITHER]
        positive_ips = [ip[0] for ip in pt_ip_filters if ip[1] == data.constants.IP_EITHER]
        negative_ips = [ip[0] for ip in negative_ip_filters if ip[1] == data.constants.IP_EITHER]
        if len(client_ips) < 1:
            raise ValueError("This strategy requires a valid source+destination (IP_EITHER) IP/subnet in the input filter!")
        self.debug_print("We assume the following clients within the censor's network are being watched: {}.".format(', '.join(client_ips)))
        self.debug_print("The following clients within the censor's network are using PT: {}.".format(', '.join(positive_ips)))
        self.debug_print("The following clients within the censor's network are not using PT: {}.".format(', '.join(negative_ips)))

        # Now the modified setup.
        self.debug_print("Loading traces...")
        self._run(merged_filters, [], pt_collection=pt_collection, negative_collection=None)
        # Rewrite the membership due to use of mixed pcap.
        self.set_case_membership([ip[0] for ip in pt_ip_filters if ip[1] == data.constants.IP_EITHER],
                                 [ip[0] for ip in negative_ip_filters if ip[1] == data.constants.IP_EITHER])
        # Threshold at which to decide to block IP in validation, dynamic
        # adjustment based on percentile of remote host occurrences if unset.
        dynamic_adjustment = True
        if decision_threshold is not None and isinstance(decision_threshold, int):
            self._decision_threshold = decision_threshold
            self.debug_print("Manually setting {} as the threshold at which to decide to block IP in validation.".format(self._decision_threshold))
            dynamic_adjustment = False

        self.debug_print("Loaded {} mixed traces".format(len(self._pt_traces)))
        self.debug_print("- Segmenting traces into {} second windows...".format(self.TIME_SEGMENT_SIZE))
        time_windows = analytics.traffic.window_traces_time_series(self._pt_traces, self.TIME_SEGMENT_SIZE*1000000, sort=False)
        self._pt_traces = None # Releases memory when processing large files.
        self.debug_print("In total we have {} time segments.".format(len(time_windows)))

        self.debug_print("- Extracting feature rows from windows in time segments...")
        features = []
        labels = []
        window_ips = []
        negative_ips = set([])
        all_subnets = [data.utils.build_subnet(ip) for ip in client_ips]
        known_PT_subnets = [data.utils.build_subnet(ip) for ip in positive_ips]

        # For dynamic decision threshold adjustment, in real operation can be
        # adjusted based on previous operations.
        target_ip_occurrences = defaultdict(int)

        for time_window in time_windows:
            traces_by_client = analytics.traffic.group_traces_by_ip_fixed_size(time_window, all_subnets, self.WINDOW_SIZE)

            for client_target in traces_by_client:

                # Mark the shared target.
                window_ip = client_target[1]

                # Generate training and validation labels.
                client = client_target[0]
                if any([i.overlaps(data.utils.build_subnet(client)) for i in known_PT_subnets]):
                    label = 1 # PT traffic.
                else:
                    label = 0 # non-PT traffic.
                    negative_ips.add(window_ip) # Recorded regardless of feature exclusion.

                for window in traces_by_client[client_target]:
                    # Extract features, IP information not needed as each window will
                    # contain one individual client's traffic with a single only.
                    feature_dict, _, _ = analytics.traffic.get_window_stats(window, [client])
                    if any([(feature_dict[i] is None) or isnan(feature_dict[i]) for i in feature_dict]):
                        continue

                    # Commit this window if the features came back fine.
                    features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])
                    labels.append(label)
                    window_ips.append(window_ip)
                    target_ip_occurrences[window_ip] += 1

        time_windows = []
        traces_by_client = []

        self.debug_print("Extracted {} rows of features.".format(len(features)))
        self.debug_print("Of which {} rows represent windows containing PT traces, {} rows don't.".format(labels.count(1), labels.count(0)))
        if len(features) < 1:
            raise ValueError("No feature rows to work with, did you misconfigure the input filters?")

        # Dynamic adjustment of decision threshold.
        if dynamic_adjustment:
            threshold = floor(np.percentile(list(target_ip_occurrences.values()), self.DYNAMIC_THRESHOLD_PERCENTILE))
            self._decision_threshold = threshold
            self.debug_print("Dynamically setting {} ({} percentile) as the threshold at which to decide to block IP in validation.".format(self._decision_threshold, self.DYNAMIC_THRESHOLD_PERCENTILE))

        all_features = np.asarray(features, dtype=np.float64)
        all_labels = np.asarray(labels, dtype=np.int8)
        features = []
        labels = []
        target_ip_occurrences = []

        # Rescale to zero centered uniform variance data.
        self._strategic_states['all_features'] = preprocessing.scale(all_features,
         axis=0, copy=False)
        self._strategic_states['all_feature_labels'] = all_labels
        self._strategic_states['all_ips'] = window_ips
        self._strategic_states['negative_unique_ips'] = len(negative_ips)
        all_features = []
        all_labels = []
        window_ips = []
        negative_ips = None

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
        self.debug_print("IPs classified as PT (block at {} occurrences):".format(self._decision_threshold))
        self.debug_print(', '.join([str(i) for i in sorted(list(self._strategic_states[best_fpr_run]["ip_occurrences"].items()), key=itemgetter(1), reverse=True)]))

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # Shorter test.
    # mixed_path = os.path.join(parent_path, 'examples', 'local', 'meeklong_unobfuscatedlong_merge.pcap')
    # detector = LRStrategy(mixed_path)
    # detector.run(pt_ip_filters=[('192.168.0.42', data.constants.IP_EITHER)],
    #     negative_ip_filters=[('172.28.195.198', data.constants.IP_EITHER)])
    # detector.clean_up_mongo()
    # print(detector.report_blocked_ips())
    # exit(0)

    mixed_path = os.path.join(parent_path, 'examples', 'local', argv[1])
    detector = LRStrategy(mixed_path)
    detector.run(pt_ip_filters=[(argv[2], data.constants.IP_EITHER)],
     negative_ip_filters=[(argv[3], data.constants.IP_EITHER)],
     pt_collection=argv[4], negative_collection=None)
    print(detector.report_blocked_ips())
