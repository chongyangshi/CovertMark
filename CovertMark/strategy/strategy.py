import analytics, data

from abc import ABC, abstractmethod
from datetime import date, datetime

class AbstractDetectionStrategy(ABC):
    """
    An abstract class of a pluggable transport detection strategy, including
    parsing of positive and negative test traces, positive case splitting,
    performing analytics, and reporting results. Implement this class to produce
    individual strategies.
    """

    NAME = "Default Strategy"
    DESCRIPTION = "A description of this strategy here."
    MONGO_KEY = "DefaultStrategy" # Alphanumeric key for MongoDB.

    def __init__(self, pt_pcap, negative_pcap=None):
        self.__pt_parser = data.parser.PCAPParser(pt_pcap)
        if negative_pcap is not None:
            self.__neg_parser = data.parser.PCAPParser(negative_pcap)
        else:
            self.__neg_parser = None

        # Names of MongoDB collections.
        self._pt_collection = None
        self._neg_collection = None

        # Lists of traces to be loaded.
        self._traces_loaded = False
        self._pt_traces = []
        self._pt_test_traces = []
        self._pt_validation_traces = []
        self._pt_split = False
        self._neg_traces = []

        # The strategic filter to examine a subset of loaded traces.
        self._strategic_packet_filter = {}


    def parse_packets(self, pt_filters, negative_filters=[]):
        """
        Parse both positive and negative test traces stored in the PCAP files.

        N.B. Filters at this stage are intended to be used to remove unrelated
        traces accidentally captured in the process, so that they do not affect
        testing/training of positive case analysis. If the analysis strategy
        only examines a subset of all PT traffic (e.g. client-to-server-only),
        its filters should be set separately in self.set_strategic_filter.

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

        assert(MONGO_KEY.isalnum)

        self.__pt_parser.set_ip_filter(pt_filters)
        desp = MONGO_KEY + "Positive" + date.today().strftime("%Y%m%d")
        self._pt_collection = self.__pt_parser.load_and_insert_new(description=desp)

        # Parse negative traces if pcap set.
        if self.__neg_parser is not None:
            self.__neg_parser.set_ip_filter(negative_filters)
            desp = MONGO_KEY + "Negative" + date.today().strftime("%Y%m%d")
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


    def load_into_memory(self):
        """
        Load parsed positive (and if set, negative) test traces from MongoDB
        into runtime memory for analysis, applying self._strategic_filter to
        both.
        :returns: True if successfully loaded, False otherwise.
        """

        self.__reader = data.retrieve.Retriever()

        self.__reader.select(self._pt_collection)
        self._pt_traces = self.__reader.retrieve(trace_filter=self._strategic_packet_filter)

        if len(self._pt_traces) == 0:
            return False

        # If no negative traces pcap parsed, we finish here.
        if self._neg_collection is None:
            self._traces_loaded = True
            return True

        self.__reader.select(self._neg_collection)
        self._neg_traces = self.__reader.retrieve(trace_filter=self._strategic_packet_filter)

        if len(self._neg_traces) == 0:
            return False

        self._traces_loaded = True
        return True


    def pt_split(self, test_proportion=0.5):
        """
        Gatekeeper method for self._pt_split, ensuring that it is called after
        before traces have been loaded from MongoDB into memory. Performs an
        implicit trace load if not yet loaded.
        :param test_proportion: a test/validation set split proportion.
        :returns: result from self._pt_split.
        """

        if not self._traces_loaded:
            self.load_into_memory()

        return self._pt_split(test_proportion)


    @abstractmethod
    def _set_strategic_filter(self, strategic_filter):
        """
        While packets not related to the PT in the positive case should have
        been removed from positive traces when parsing the pcap file
        (self.parse_packets), if this strategy only examines certain packets
        in the traces, such as client-to-server packets only, they should be
        specified here in the strategic filter. The syntax follows MongoDB
        queries on the trace syntax:
        (see CovertMark.data.parser.PCAPParser.load_packet_info.)
        Implement this method by assigning to self._strategic_packet_filter
        :param strategic_filter: MongoDB trace querying filter, examples:
         - Only examine TCP packets: {"tcp_info": {"$ne": None}}
         - Only examine TCP packets with non-empty payload:
            {"tcp_info": {"$ne": None}, "tcp_info.payload": {"$ne": b''}}
        :returns: None
        """


    @abstractmethod
    def _pt_split(self, test_proportion):
        """
        Perform a split of positive test traces into test and validation sets if
        required by the strategy. Each call to this strategy should set
        self._pt_split to True, and repopulate self._pt_test_traces and
        self._pt_validation_traces from self._pt_traces. Implement this method.
        :param test_proportion: passed in from self.pt_split
        :returns: None
        """
