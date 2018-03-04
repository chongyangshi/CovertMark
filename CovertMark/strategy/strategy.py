import analytics, data

import os
from abc import ABC, abstractmethod
from datetime import date, datetime
from collections import defaultdict

class DetectionStrategy(ABC):
    """
    An abstract class of a pluggable transport detection strategy, including
    parsing of positive and negative test traces, positive case splitting,
    performing analytics, and reporting results. Implement this class to produce
    individual strategies.
    """

    NAME = "Default Strategy"
    DESCRIPTION = "A description of this strategy here."
    _MONGO_KEY = "DefaultStrategy" # Alphanumeric key for MongoDB.
    _DEBUG_PREFIX = _MONGO_KEY # For debug messages only, split for inheritance convenience.

    def __init__(self, pt_pcap, negative_pcap=None, recall_pcap=None, debug=False):
        self.__debug_on = debug
        self.__pt_pcap = pt_pcap
        if negative_pcap is not None:
            self.__negative_pcap = negative_pcap
        else:
            self.__negative_pcap = None
        if recall_pcap is not None:
            self.__recall_pcap = recall_pcap
        else:
            self.__recall_pcap = None

        self.__reader = data.retrieve.Retriever()

        # MongoDB collections.
        self._pt_collection = None
        self._neg_collection = None
        self._recall_collection = None
        self._pt_collection_total = 0
        self._neg_collection_total = 0
        self._recall_collection_total = 0

        # Lists of traces to be loaded.
        self._traces_loaded = False
        self._pt_traces = []
        self._pt_test_traces = []
        self._pt_validation_traces = []
        self._pt_split = False
        self._neg_traces = []
        self._recall_traces = []
        self._positive_subnets = []
        self._negative_subnets = []
        self._recall_subnets = []

        # The strategic filter to examine a subset of loaded traces.
        self._strategic_packet_filter = {}

        # The strategy's internal states.
        self._strategic_states = {}
        self._true_positive_rate = None
        self._false_positive_rate = None
        self._false_positive_blocked_rate = 0
        self._negative_unique_ips = 0
        self._negative_blocked_ips = set([])
        self._recall_rate = None

        # For debug outputs, overwrite if required.
        self.DEBUG = debug
        self._performance_csv = "Occurrence Threshold (pct),FPR (% Innocent packets incorrectly blocked),FNR (% PT packets missed),% Innocent IP's blocked overall\n"

        # For windowing-based strategies only.
        self._window_size = 25
        self._target_ip_occurrences = defaultdict(int)


    def _parse_PT_packets(self, pt_filters):
        """
        Parse positive test traces stored in the PCAP file.

        N.B. Filters at this stage are intended to be used to remove unrelated
        traces accidentally captured in the process, so that they do not affect
        testing/training of positive case analysis. If the analysis strategy
        only examines a subset of all PT traffic (e.g. client-to-server-only),
        its filters should be set separately in self.set_strategic_filter.

        This separation is by design so that source/destination import filtering
        can be changed dynamically at each run based on the actual pcap, while
        strategic filtering is expected to remain unchanged.

        :param pt_filters: Parser filters for PT trace parsing. Presented as a
            list of tuples to parse upstream or downstream packets only. e.g.
            [('192.168.0.42', data.constants.IP_SRC),
             ('13.32.68.100', data.constants.IP_DST)]
            For filter matching rules, see CovertMark.data.parser.PCAPParser.set_ip_filter.
            For an empty (allow-all) filter, use {}.
        :returns: True if a non-zero amount of traces were parsed, False otherwise.
        """

        assert(self._MONGO_KEY.isalnum)

        self.__pt_parser = data.parser.PCAPParser(self.__pt_pcap)


        self.__pt_parser.set_ip_filter(pt_filters)
        self.set_case_membership([i[0] for i in pt_filters], None)
        desp = self._MONGO_KEY + "Positive" + date.today().strftime("%Y%m%d")
        self._pt_collection = self.__pt_parser.load_and_insert_new(description=desp)

        if self._pt_collection:
            return True
        else:
            return False


    def _parse_negative_packets(self, negative_filters):
        """
        Parse negative test traces stored in the PCAP file.
        :param negative_filters: same format as positive filters above. Allow-all
            by default.
        :returns: True if a non-zero amount of traces were parsed, False otherwise.
        """

        assert(self._MONGO_KEY.isalnum)

        self.__neg_parser = data.parser.PCAPParser(self.__negative_pcap)
        self.__neg_parser.set_ip_filter(negative_filters)
        self.set_case_membership(None, [i[0] for i in negative_filters])
        desp = self._MONGO_KEY + "Negative" + date.today().strftime("%Y%m%d")
        self._neg_collection = self.__neg_parser.load_and_insert_new(description=desp)
        if self._neg_collection:
            return True
        else:
            return False


    def _parse_recall_packets(self, recall_filters):
        """
        Parse positive recall test traces stored in the PCAP file.
        :param recall_filters: same format as positive filters above. Allow-all
            by default.
        :returns: True if a non-zero amount of traces were parsed, False otherwise.
        """

        assert(self._MONGO_KEY.isalnum)

        self.__recall_parser = data.parser.PCAPParser(self.__recall_pcap)
        self.__recall_parser.set_ip_filter(recall_filters)
        desp = self._MONGO_KEY + "Recall" + date.today().strftime("%Y%m%d")
        self._recall_collection = self.__recall_parser.load_and_insert_new(description=desp)
        if self._recall_collection:
            return True
        else:
            return False


    def _load_into_memory(self):
        """
        Load parsed positive (and if set, negative) test traces from MongoDB
        into runtime memory for analysis, applying self._strategic_filter to
        both.
        :returns: True if successfully loaded, False otherwise.
        """

        self.__reader.select(self._pt_collection)
        self.debug_print("- Retrieving from {}...".format(self.__reader.current()))
        self._pt_traces = self.__reader.retrieve(trace_filter=self._strategic_packet_filter)
        self._pt_collection_total = self.__reader.count(trace_filter={})

        if len(self._pt_traces) == 0:
            return False

        # Reload positive filters.
        pt_filters = self.__reader.get_input_filters()
        if pt_filters:
            pt_clients = [i[0] for i in pt_filters if i[1] in [data.constants.IP_SRC, data.constants.IP_EITHER]]
            self.debug_print("- Automatically setting the corresponding input filters for positive clients: {}".format(str(pt_clients)))
            self.set_case_membership(pt_clients, None)
        else:
            self.debug_print("Input filters attached to the positive collection do not exist or are invalid, must be manually set with set_case_membership().")


        # If no negative traces pcap parsed, we skip it.
        if self._neg_collection is not None:
            self.__reader.select(self._neg_collection)
            self.debug_print("- Retrieving from {}...".format(self.__reader.current()))
            self._neg_traces = self.__reader.retrieve(trace_filter=self._strategic_packet_filter)
            self._neg_collection_total = self.__reader.count(trace_filter={})

            # Record distinct destination IP addresses for stat reporting.
            self._negative_unique_ips = self.__reader.distinct('dst')

            if len(self._neg_traces) == 0:
                return False

            # Reload negative filters.
            neg_filters = self.__reader.get_input_filters()
            if neg_filters:
                neg_clients = [i[0] for i in neg_filters if i[1] in [data.constants.IP_SRC, data.constants.IP_EITHER]]
                self.debug_print("- Automatically setting the corresponding input filters for negative clients: {}".format(str(neg_clients)))
                self.set_case_membership(None, neg_clients)
            else:
                self.debug_print("Input filters attached to the positive collection do not exist or are invalid, must be manually set with set_case_membership().")


        # If no recall traces pcap parsed, we finish here.
        if self._recall_collection is None:
            self._traces_loaded = True
            return True

        self.__reader.select(self._recall_collection)
        self.debug_print("- Retrieving from {}...".format(self.__reader.current()))
        self._recall_traces = self.__reader.retrieve(trace_filter=self._strategic_packet_filter)
        self._recall_collection_total = self.__reader.count(trace_filter={})

        # Set recall subnets.
        recall_filters = self.__reader.get_input_filters()
        if recall_filters:
            self._recall_subnets = [data.utils.build_subnet(i[0]) for i in recall_filters if i[1] in [data.constants.IP_SRC, data.constants.IP_EITHER]]
            self.debug_print("Automatically set the corresponding input filters for recall clients: {}.".format(str([i[0] for i in recall_filters])))

        if len(self._recall_traces) == 0:
            return False

        self.debug_print("Positive recall traces loaded.")

        self._traces_loaded = True

        return True


    def set_case_membership(self, positive_ips, negative_ips):
        """
        Set an internal list of positive and negative subnets for membership
        checking with self.in_positive_filter and self.in_negative_filter. This
        is useful if a mixed pcap needs to be parsed into self._pt_traces only.
        If only one of the two needs to be set, pass in None in the corresponding
        other parameter.
        :param positve_ips: list of subnets that are positive, i.e. PT clients.
        :param negative_ips: list of subnets that are negative, i.e. innocent
            clients.
        """

        if positive_ips:
            positive_subnets = [data.utils.build_subnet(i) for i in positive_ips]
            if all(positive_subnets):
                self._positive_subnets = positive_subnets

        if negative_ips:
            negative_subnets = [data.utils.build_subnet(i) for i in negative_ips]
            if all(negative_subnets):
                self._negative_subnets = negative_subnets

        return True


    def in_positive_filter(self, ip):
        """
        :param input IP or subnet.
        :returns True if IP or subnet specified is in the positive input filter,
            False otherwise, or if input invalid.
        """

        ip_subnet = data.utils.build_subnet(ip)
        if not ip_subnet:
            return False

        for i in self._positive_subnets:
            if i.overlaps(ip_subnet):
                return True

        return False


    def in_negative_filter(self, ip):
        """
        :param input IP or subnet.
        :returns True if IP or subnet specified is in the negative input filter,
            False otherwise, or if input invalid.
        """

        ip_subnet = data.utils.build_subnet(ip)
        if not ip_subnet:
            return False

        for i in self._negative_subnets:
            if i.overlaps(ip_subnet):
                return True

        return False


    def _run_on_positive(self, **kwargs):
        """
        Wrapper for self.positive_run, testing the detection strategy on positive
        PT traces.
        """

        if not self._pt_collection:
            return False

        if not self._traces_loaded:
            self._load_into_memory()

        self._true_positive_rate = self.positive_run(**kwargs)
        return self._true_positive_rate


    def _run_on_negative(self, **kwargs):
        """
        Wrapper for the optional self.negative_run, testing the detection
        strategy on negative traces.
        """

        if not self._neg_collection:
            return False

        if not self._traces_loaded:
            self._load_into_memory()

        self._false_positive_rate = self.negative_run(**kwargs)
        self._false_positive_blocked_rate = float(len(self._negative_blocked_ips)) / self._negative_unique_ips
        return self._false_positive_rate


    def _run_on_recall(self, **kwargs):
        """
        Wrapper for the optional self.recall_run, testing the trained classifier
        on positive recall traces.
        """

        if not self._recall_collection:
            return False

        if not self._traces_loaded:
            self._load_into_memory()

        self._recall_rate = self.recall_run(**kwargs)
        return self._recall_rate



    def _split_pt(self, split_ratio=0.7):
        """
        Gatekeeper method for self.test_validation_split, ensuring that it is
        called after traces have been loaded from MongoDB into memory. Performs
        an implicit trace load if not yet loaded. Call this method to perform
        a split.
        Do not override this method, but override test_validation_split below.
        :param split_ratio: the proportion of positive traces used as test
            rather than validation in a split.
        """

        if not self._traces_loaded:
            self._load_into_memory()

        splits = self.test_validation_split(split_ratio)
        if splits and isinstance(splits, tuple):
            test, validation = splits
            # Only validate split if a non-empty split has been performed.
            if len(test) > 0 or len(validation) > 0:
                self._pt_test_traces = test
                self._pt_validation_traces = validation
                self._pt_split = True


    def debug_print(self, message):
        """
        Prints a debug message to the console, useful for debugging. Appends the
        strategy name and timestamp automatically.
        """

        if self.__debug_on == False:
            return

        msg = "[" + self._DEBUG_PREFIX + "] " + str(datetime.now()) +" : " + message
        print(msg)


    def _run(self, pt_ip_filters, negative_ip_filters, pt_collection=None,
     negative_collection=None, test_recall=False, recall_ip_filters=[],
     recall_collection=None):
        """
        Inner method to execute the required portion of strategy setup.
        To skip parsing traces again and use existing collections in MongoDB,
        both pt_collection and negative_collection need to be set to valid names.
        Recall used for evaluation of strategy itself only, not for general use.
        """

        self.debug_print("Executing detection strategy: " + self.NAME)
        self.debug_print(self.DESCRIPTION)

        reparsing_positive = True

        if not self.__negative_pcap:
            reparsing_negative = False
        else:
            reparsing_negative = True

        if pt_collection is not None:
            if self.__reader.select(pt_collection):
                reparsing_positive = False
                self._pt_collection = pt_collection
                self.debug_print("Loading existing PT traces...")
            else:
                self.debug_print("Re-parsing PT PCAP file as {} does not exist in MongoDB...".format(pt_collection))

        if reparsing_positive:
            self.debug_print("- Parsing PT PCAP...")
            if self._parse_PT_packets(pt_ip_filters):
                self.debug_print("Parsed PCAP file according to input positive IP filters.")
            else:
                raise RuntimeError("! Failure to parse positive PCAP files.")

        if negative_collection is not None:
            if self.__reader.select(negative_collection):
                reparsing_negative = False
                self._neg_collection = negative_collection
                self.debug_print("Loading existing negative traces...")
            else:
                self.debug_print("Re-parsing negative traces as {} does not exist in MongoDB...".format(negative_collection))

        if reparsing_negative:
            self.debug_print("- Parsing negative PCAP...")
            if self._parse_negative_packets(negative_ip_filters):
                self.debug_print("Parsed PCAP file according to input negative IP filters.")
            else:
                raise RuntimeError("! Failure to parse negative PCAP file.")

        if test_recall:
            self.debug_print("This run will test the positive recall of the best classifier.")
            if self.__reader.select(recall_collection):
                self._recall_collection = recall_collection
                self.debug_print("Loading existing recall traces...")
            else:
                self.debug_print("- Attempting to parse recall PCAP as specified recall collection does not exist.")
                if self._parse_recall_packets(recall_ip_filters):
                    self.debug_print("Parsed PCAP file according to input recall IP filters.")
                else:
                    raise RuntimeError("! Failure to parse recall PCAP file.")

        self.debug_print("- Setting initial strategic filter...")
        self.set_strategic_filter()
        self.debug_print("Pre-examination filter: {}".format(self._strategic_packet_filter))

        self.debug_print("- Loading packets according to the initial strategic filter...")
        self._load_into_memory()
        self.debug_print("Positive: {} traces, examining {}.".format(self._pt_collection_total, len(self._pt_traces)))
        self.debug_print("Negative: {} traces, examining {}.".format(self._neg_collection_total, len(self._neg_traces)))
        self.debug_print("Positive Recall: {} traces, examining {}.".format(self._recall_collection_total, len(self._recall_traces)))


    def clean_up_mongo(self):
        """
        Deletes the temporary MongoDB collection used to store traces. This
        prevents further runs from being carried out, therefore to be used at
        the end of execution only.
        """

        self.__pt_parser.clean_up(self._pt_collection)
        if self._neg_collection is not None:
            self.__neg_parser.clean_up(self._neg_collection)


    def record_performance(self, FNR, FPR, pct_ip_blocked, threshold=None):
        """
        Add a line of record to allow printing performance stats in CSV.
        :param FNR: false negative rate reported (0-1), TPR = 1 - FNR.
        :param FPR: false positive rate reported (0-1), TNR = 1 - FPR.
        :param pct_ip_blocked: percentage of IPs falsely blocked (0-100).
        :param threshold: percentage of occurrence threshold if used, None
            by default.
        :returns: True if record successfully added, False otherwise.
        """

        if not (0 <= FNR <= 1) or not (0 <= FPR <= 1):
            return False

        if not (0 <= pct_ip_blocked <= 100):
            return False

        if threshold is None or not isinstance(threshold, int):
            threshold = 0

        # Now convert ratios to percentages.
        self._performance_csv += "{},{:0.2f},{:0.2f},{:0.2f}\n".format(threshold, FNR*100, FPR*100, pct_ip_blocked)

        return True


    def report_performance(self):
        """
        Return the performance record CSV as a string. Format:
        Occurrence threshold, FNR (%), FPR (%), percentage of IP falsely blocked
        :returns: performance CSV string with embedded linebreaks.
        """

        return self._performance_csv


    # ========================To be implemented below==========================#

    def run(self, pt_ip_filters=[], negative_ip_filters=[], pt_split=False,
     pt_split_ratio=0.7, pt_collection=None, negative_collection=None,
     test_recall=False, recall_ip_filters=[], recall_collection=None):
        """
        Run the detection strategy. See other methods for detailed syntax of
        IP and strategic filters. Override if custom procedures required, such
        as adjusting a positive run after each negative run. self._run should
        always be called at the start with the filters for setup.
        :param pt_ip_filter: input IP filter for positive test traces.
        :param negative_ip_filter: input IP filter for negative test traces.
        :param pt_split: True if splitting positive test cases into test and
            validation sets. False otherwise.
        :param pt_split_ratio: if pt_split is set to True, this is the ratio the
            test set will occupy versus the validation set.
        :param pt_collection: set pt_collection to be the name of an existing
            collection in MongoDB to skip parsing again.
        :param negative_collection: set negative_collection to be the name of an
            existing collection in MongoDB to skip parsing again.
        :param test_recall: if True, the strategy will also test the classifier
            on unseen positive recall traces to cross validate.
        :param recall_ip_filters: input IP filter for recall test traces.
        :param recall_collection: set recall_collection to be the name of an
            existing collection in MongoDB to skip parsing again.
        :returns: tuple(self._true_positive_rate, self._false_positive_rate)
        """

        self._run(pt_ip_filters, negative_ip_filters,
         pt_collection=pt_collection, negative_collection=negative_collection)

        if pt_split:
            self.debug_print("- Splitting positive test traces into the ratio of {}/{}".format(pt_split_ratio, 1-pt_split_ratio))
            self._split_pt(pt_split_ratio)

        self.debug_print("- Running detection strategy on positive test traces...")
        self._true_positive_rate = self._run_on_positive()
        self.debug_print("Reported true positive rate: {}".format(self._true_positive_rate))

        if self._neg_collection is not None:
            self.debug_print("- Validating detection strategy on negative test traces...")
            self._false_positive_rate = self._run_on_negative()
            self.debug_print("Reported false positive rate: {}".format(self._false_positive_rate))
            self.debug_print("False positive IPs blocked rate: {}".format(self._false_positive_blocked_rate))

        if test_recall:
            self.debug_print("- Validating best strategy on positive recall traces...")
            self._recall_rate = self._run_on_recall()
            self.debug_print("Reported positive recall rate: {}".format(self._recall_rate))

        return (self._true_positive_rate, self._false_positive_rate)


    @abstractmethod
    def set_strategic_filter(self, new_filter={}):
        """
        While packets not related to the PT in the positive case should have
        been removed from positive traces when parsing the pcap file
        (self._parse_PT_packets), if this strategy only examines certain packets
        in the traces, such as client-to-server packets only, they should be
        specified here in the strategic filter. The syntax follows MongoDB
        queries on the trace syntax:
        (see CovertMark.data.parser.PCAPParser.load_packet_info.)
        Implement this method by assigning to self._strategic_packet_filter,
        optionally you can call this method again between positve and negative
        runs to adjust the filter as necessary with a new filter.
        self._load_into_memory() should be called again after each change of
        filter to reload the postive and negative traces with the new filter.
        :param new_filter: MongoDB trace querying filter, examples:
         - Only examine TCP packets: {"tcp_info": {"$ne": None}}
         - Only examine TCP packets with non-empty payload:
            {"tcp_info": {"$ne": None}, "tcp_info.payload": {"$ne": b''}}
        """

        self._strategic_packet_filter = new_filter


    def test_validation_split(self, split_ratio):
        """
        Perform a split of positive test traces into test and validation sets if
        required by the strategy. Override this method if split required, otherwise,
        keep it returning a tuple of empty lists as followed.
        :param split_ratio: passed in from self._split_pt
        :returns: tuple(test_traces, validation_traces)
        """

        return ([], [])


    @abstractmethod
    def positive_run(self, **kwargs):
        """
        Perform PT detection strategy on positive test traces.
        Available data:
        - The number of positive traces in the collection under input filter:
        --- self._pt_collection_total
        - All positive test traces under strategic filter:
        --- self._pt_traces
        - If self._pt_split is True (split into test and validation traces)
        --- self._pt_test_traces
        --- self._pt_validation_traces
        Assign to self._strategic_states if information needs to be stored
        between runs or carried over into negative test runs.
        Implement this method.
        :returns: True positive identification rate as your strategy interprets.
        """

        return 0


    def negative_run(self, **kwargs):
        """
        Perform PT detection strategy on negative test traces to test for False
            Positive rate.
        Available data:
        - The number of negative traces in the collection under input filter:
        --- self._neg_collection_total
        - All negative test traces under strategic filter:
        --- self._neg_traces
        Assign to self._strategic_states if information needs to be stored
        between runs or carried over into positive test runs.
        Add to self._negative_blocked_ips to tally blocked IPs for reporting.
        Implement this method, simply return 0 if no negative trace required.
        :returns: False positive identification rate as your strategy interprets.
        """

        return 0


    def recall_run(self, **kwargs):
        """
        Perform a recall on unseen positive traces specified in self._recall_traces.
        You should carry over best parameters obtained from positive and negative
        runs or a best classifier through self._strategic_states or subclass
        variables.
        It is assumed that after the recall input filter and the strategic filter,
        all packets in self._recall_traces are positive traces unseen during
        positve and negative runs prior. self._recall_subnets should have been
        set after the main runs.
        :returns: the positive recall rate.
        """

        return 0


    def report_blocked_ips(self):
        """
        Return a Wireshark-compatible filter expression to allow viewing blocked
        traces in Wireshark. Useful for studying false positives. Overwrite
        this method if needed, draw data from self._negative_blocked_ips as set
        above.
        :returns: a Wireshark-compatible filter expression string.
        """

        return ""
