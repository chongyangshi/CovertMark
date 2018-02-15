import analytics, data
from strategy.strategy import DetectionStrategy

import os
from datetime import date, datetime
from operator import itemgetter
from math import log1p, isnan
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


    def __init__(self, pt_pcap, negative_pcap=None):
        super().__init__(pt_pcap, negative_pcap, self.DEBUG)
        self.LR = linear_model.LogisticRegression(penalty='l1', dual=False,
         solver='saga', n_jobs=-1, max_iter=5000)


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

        split = model_selection.train_test_split(self._strategic_states['all_features'],
         self._strategic_states['all_feature_labels'], train_size=split_ratio,
          shuffle=True)
        self._strategic_states['training_labels'] = split[2]
        self._strategic_states['validation_labels'] = split[3]

        return (split[0], split[1])


    def positive_run(self, **kwargs):
        """
        Perform logistic regression on the training/testing dataset, and validate
        overfitting on validation dataset.
        """

        self.debug_print("- Logistic Regression training with L1 penalisation and SAGA solver...")
        self.LR.fit(self._pt_test_traces, self._pt_test_labels)

        self.debug_print("- Logistic Regression validation...")
        prediction = self.LR.predict(self._pt_validation_traces)

        total_positives = 0
        true_positives = 0
        false_positives = 0
        total_negatives = 0
        true_negatives = 0
        false_negatives = 0
        for i in range(0, len(prediction)):
            if prediction[i] == 1: # Positive identification
                total_positives += 1
                if self._pt_validation_labels[i] == 1:
                    true_positives += 1
                else:
                    false_positives += 1
            else:
                total_negatives += 1
                if self._pt_validation_labels[i] == 0:
                    true_negatives += 1
                else:
                    false_negatives += 1

        self._strategic_states["total"] = total_positives + total_negatives
        self._strategic_states["TPR"] = float(true_positives) / total_positives
        self._strategic_states["FPR"] = float(false_positives) / total_positives
        self._strategic_states["TNR"] = float(true_negatives) / total_negatives
        self._strategic_states["FNR"] = float(false_negatives) / total_negatives

        return self._strategic_states["TPR"]


    def negative_run(self):
        """
        Not used at this time, as FPR combined into self.positive_run.
        """

        return None


    def report_blocked_ips(self):
        """
        It is not possible to pin point blocked IPs in the false positive cases,
        as the traces have been windowed.
        """

        return "Unavailable for logistic regression."


    def run(self, pt_ip_filters=[], negative_ip_filters=[], pt_split=True, pt_split_ratio=0.5):
        """
        Overriding default run() to test over multiple block sizes and p-value
        thresholds.
        """

        self._run(pt_ip_filters, negative_ip_filters)

        self.debug_print("Loaded {} positive traces, {} negative traces.".format(len(self._pt_traces), len(self._neg_traces)))
        self.debug_print("- Applying windowing to the traces...")
        positive_windows = analytics.traffic.window_traces_fixed_size(self._pt_traces, 100)
        negative_windows = analytics.traffic.window_traces_fixed_size(self._neg_traces, 100)

        self.debug_print("- Extracting features from windowed traffic...")
        if (not any([i[1] == data.constants.IP_EITHER for i in pt_ip_filters])) or \
            (not any([i[1] == data.constants.IP_EITHER for i in negative_ip_filters])):
            raise ValueError("This strategy requires a valid source+destination IP/subnet set for the input filters!")

        positive_features = []
        for ip in pt_ip_filters:
            if ip[1] == data.constants.IP_EITHER:
                client_ip = ip[0]
                break
        self.debug_print("The suspected PT client(s) in positive cases are assumed as {}.".format(client_ip))
        for window in positive_windows:
            feature_dict = analytics.traffic.get_window_stats(window, client_ip)
            if any([(not feature_dict[i]) or isnan(feature_dict[i]) for i in feature_dict]):
                continue
            positive_features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])

        negative_features = []
        for ip in negative_ip_filters:
            if ip[1] == data.constants.IP_EITHER:
                client_ip = ip[0]
                break
        self.debug_print("The suspected PT client(s) in negative cases are assumed as {}.".format(client_ip))
        for window in negative_windows:
            feature_dict = analytics.traffic.get_window_stats(window, client_ip)
            if any([(not feature_dict[i]) or isnan(feature_dict[i]) for i in feature_dict]):
                continue
            negative_features.append([i[1] for i in sorted(feature_dict.items(), key=itemgetter(0))])

        self.debug_print("Prepared {} positive windows, {} negative windows.".format(\
         len(positive_features), len(negative_features)))
        all_features = positive_features + negative_features
        all_features = np.asarray(all_features, dtype=np.float64)
        all_labels = [1 for i in range(len(positive_features))] + [0 for i in range(len(negative_features))]
        all_labels = np.asarray(all_labels, dtype=np.int8)

        # Rescale to zero centered uniform variance data.
        self._strategic_states['all_features'] = preprocessing.scale(all_features,
         axis=0, copy=False)
        self._strategic_states['all_feature_labels'] = all_labels
        self.debug_print("- Splitting training/validation by the ratio of {}.".format(pt_split_ratio))
        self._split_pt(pt_split_ratio)

        if not self._pt_split:
            self.debug_print("Training/validation case splitting failed, check data.")
            return False

        # self._pt_test_traces / self._pt_validation_traces set by split wrapper.
        self._pt_test_labels = self._strategic_states['training_labels']
        self._pt_validation_labels = self._strategic_states['validation_labels']

        # Stored states no longer required.
        self._strategic_states = {}

        # Run training and validation.
        self._run_on_positive()

        self.debug_print("Results of validation: ")
        self.debug_print("Total: {}".format(self._strategic_states["total"]))
        self.debug_print("TPR: {:0.2f}%, TNR: {:0.2f}%".format(\
         self._strategic_states['TPR']*100, self._strategic_states['TNR']*100))
        self.debug_print("FPR: {:0.2f}%, FNR: {:0.2f}%".format(\
         self._strategic_states['FPR']*100, self._strategic_states['FNR']*100))

        return (self._true_positive_rate, self._false_positive_rate)


if __name__ == "__main__":
    parent_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    # Longer ACS Test.
    lr_path = os.path.join(parent_path, 'examples', 'local', 'meeklong.pcap')
    unobfuscated_path = os.path.join(parent_path, 'examples', 'local', 'unobfuscatedlong.pcap')
    detector = LRStrategy(lr_path, unobfuscated_path)
    detector.run(pt_ip_filters=[('192.168.0.42', data.constants.IP_EITHER)],
        negative_ip_filters=[('172.28.195.198', data.constants.IP_EITHER)])

    detector.clean_up_mongo()
