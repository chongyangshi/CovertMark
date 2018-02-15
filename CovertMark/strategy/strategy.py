import analytics, data

import os
from abc import ABC, abstractmethod
from datetime import date, datetime

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

    def __init__(self, pt_pcap, negative_pcap=None, debug=False):
        self.__debug_on = debug
        self.__pt_parser = data.parser.PCAPParser(pt_pcap)
        if negative_pcap is not None:
            self.__neg_parser = data.parser.PCAPParser(negative_pcap)
        else:
            self.__neg_parser = None

        # MongoDB collections.
        self._pt_collection = None
        self._neg_collection = None
        self._pt_collection_total = 0
        self._neg_collection_total = 0

        # Lists of traces to be loaded.
        self._traces_loaded = False
        self._pt_traces = []
        self._pt_test_traces = []
        self._pt_validation_traces = []
        self._pt_split = False
        self._neg_traces = []

        # The strategic filter to examine a subset of loaded traces.
        self._strategic_packet_filter = {}

        # The strategy's internal states.
        self._strategic_states = {}
        self._true_positive_rate = None
        self._false_positive_rate = None
        self._false_positive_blocked_rate = 0
        self._negative_unique_ips = 0
        self._negative_blocked_ips = set([])

        # For debug outputs, overwrite if required.
        self.DEBUG = False


    def _parse_packets(self, pt_filters, negative_filters=[]):
        """
        Parse both positive and negative test traces stored in the PCAP files.

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
        :param negative_filters: Negative filters if required for housekeeping,
            although in principle they should not remove any candidate traces
            that may result in false positive detection. Allow-all by default.
        :returns: True if a non-zero amount of traces were parsed for both pcaps,
            False otherwise.
        """

        assert(self._MONGO_KEY.isalnum)

        self.__pt_parser.set_ip_filter(pt_filters)
        desp = self._MONGO_KEY + "Positive" + date.today().strftime("%Y%m%d")
        self._pt_collection = self.__pt_parser.load_and_insert_new(description=desp)

        # Parse negative traces if pcap set.
        if self.__neg_parser is not None:
            self.__neg_parser.set_ip_filter(negative_filters)
            desp = self._MONGO_KEY + "Negative" + date.today().strftime("%Y%m%d")
            self._neg_collection = self.__neg_parser.load_and_insert_new(description=desp)
            if self._pt_collection and self._neg_collection:
                return True
            else:
                return False
        else:
            if self._pt_collection:
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

        self.__reader = data.retrieve.Retriever()

        self.__reader.select(self._pt_collection)
        self.debug_print("- Retrieving from {}...".format(self.__reader.current()))
        self._pt_traces = self.__reader.retrieve(trace_filter=self._strategic_packet_filter)
        self._pt_collection_total = self.__reader.count(trace_filter={})

        if len(self._pt_traces) == 0:
            return False

        # If no negative traces pcap parsed, we finish here.
        if self._neg_collection is None:
            self._traces_loaded = True
            return True

        self.__reader.select(self._neg_collection)
        self.debug_print("- Retrieving from {}...".format(self.__reader.current()))
        self._neg_traces = self.__reader.retrieve(trace_filter=self._strategic_packet_filter)
        self._neg_collection_total = self.__reader.count(trace_filter={})

        if len(self._neg_traces) == 0:
            return False

        self._traces_loaded = True
        return True


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
        Wrapper for self.negative_run, testing the detection strategy on positive
        PT traces.
        """

        if not self._neg_collection:
            return False

        if not self._traces_loaded:
            self._load_into_memory()

        # Record distinct destination IP addresses for stat reporting.
        self._negative_unique_ips = self.__reader.distinct('dst')

        self._false_positive_rate = self.negative_run(**kwargs)
        self._false_positive_blocked_rate = float(len(self._negative_blocked_ips)) / self._negative_unique_ips
        return self._false_positive_rate


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

        msg = "[D] " + str(datetime.now()) + " " + self.NAME + ": " + message
        print(msg)


    def _run(self, pt_ip_filters, negative_ip_filters):
        """
        Inner method to execute the required portion of strategy setup.
        """

        self.debug_print("Executing detection strategy: " + self.NAME)
        self.debug_print(self.DESCRIPTION)
        if self._parse_packets(pt_ip_filters, negative_filters=negative_ip_filters):
            self.debug_print("- Parsed PCAP file(s) according to input IP filters.")
        else:
            raise RuntimeError("! Failure to parse PCAP files.")

        self.debug_print("- Setting initial strategic filter...")
        self.set_strategic_filter()
        self.debug_print("Pre-examination filter: {}".format(self._strategic_packet_filter))

        self.debug_print("- Loading packets according to the initial strategic filter...")
        self._load_into_memory()
        self.debug_print("Positive: {} traces, examining {}.".format(self._pt_collection_total, len(self._pt_traces)))
        self.debug_print("Negative: {} traces, examining {}.".format(self._neg_collection_total, len(self._neg_traces)))


    def clean_up_mongo(self):
        """
        Deletes the temporary MongoDB collection used to store traces. This
        prevents further runs from being carried out, therefore to be used at
        the end of execution only.
        """

        self.__pt_parser.clean_up(self._pt_collection)
        if self._neg_collection is not None:
            self.__neg_parser.clean_up(self._neg_collection)


    # ========================To be implemented below==========================#

    def run(self, pt_ip_filters=[], negative_ip_filters=[], pt_split=False, pt_split_ratio=0.7):
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
        :returns: tuple(self._true_positive_rate, self._false_positive_rate)
        """

        self._run(pt_ip_filters, negative_ip_filters)

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

        return (self._true_positive_rate, self._false_positive_rate)


    @abstractmethod
    def set_strategic_filter(self, new_filter={}):
        """
        While packets not related to the PT in the positive case should have
        been removed from positive traces when parsing the pcap file
        (self._parse_packets), if this strategy only examines certain packets
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


    @abstractmethod
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


    def report_blocked_ips(self):
        """
        Return a Wireshark-compatible filter expression to allow viewing blocked
        traces in Wireshark. Useful for studying false positives. Overwrite
        this method if needed, draw data from self._negative_blocked_ips as set
        above.
        :returns: a Wireshark-compatible filter expression string.
        """

        return ""
