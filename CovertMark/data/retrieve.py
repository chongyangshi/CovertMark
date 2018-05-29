from . import utils, constants, mongo

from base64 import b64decode

class Retriever:

    def __init__(self):
        self.__db = mongo.MongoDBManager(db_server=constants.MONGODB_SERVER)
        self._collection = None


    def list(self, in_string=False, match_filters=None):
        """
        Return a list of all collections of packets currently stored in MongoDB.

        :param str in_string: pre-format the output in string if True.
        :param list match_filters: a list of :mod:`CovertMark.data.constants` filter types to
            match with those of stored collections, returning only matched
            collections. If None, return all collections.
        :returns: list of traces with `{name, creation_time, description}`.
        """

        traces = self.__db.list_collections()

        if isinstance(match_filters, list):
            qualified_traces = []
            for trace in traces:
                filter_types = [i[1] for i in trace["input_filters"]]
                if set(filter_types) == set(match_filters):
                    qualified_traces.append(trace)
            traces = qualified_traces

        for trace in traces:
            trace["count"] = self.__db.count_packets(trace["name"])

        if not in_string:
            return traces

        output = "Available collections of traces:\n"

        for trace in traces:
            output += trace["name"] + ", " + trace["description"] + ", " + \
             trace["creation_time"] + ", " + str(trace["input_filters"]) + \
             ", " + str(trace["count"]) + "\n"

        if isinstance(match_filters, list):
            output += "(Only those with specified input filter types are returned.)"

        return output


    def select(self, collection_name):
        """
        Set the retriever to the collection as specified, returns False if
        specified collection does not exist or invalid.

        :param str collection_name: the name of collection to be retrieved.
        :returns: True if successfully selected, False otherwise.
        """

        if self.__db.lookup_collection(collection_name):

            self._collection = collection_name
            return True

        else:
            return False


    def get_input_filters(self):
        """
        Retrieve and validate input filter information from the collection.

        :returns: if all input filters present are valid, returns the filters,
            otherwise returns False.
        """

        collections = self.list(in_string=False)
        this_collection = None

        for collection in collections:
            if collection["name"] == self._collection:
                this_collection = collection
                break

        if not this_collection:
            return False

        if "input_filters" not in collection:
            return False

        for filter in collection["input_filters"]:
            if not utils.build_subnet(filter[0]) or filter[1] not in [constants.IP_SRC, constants.IP_DST, constants.IP_EITHER]:
                return False

        return collection["input_filters"]


    def current(self):
        """
        Get the current collection selected.

        :returns: the current collection of packets selected. None if none selected.
        """

        return self._collection


    def count(self, trace_filter={}):
        """
        Count the number of packets in the currently selected MongoDB collection,

        :param dict trace_filter: a MongoDB query filter, which can be empty --
            in which case all packets will be counted.
        :returns: the number of packets matching the filter in the currently
            selected collection.
        """

        return self.__db.count_packets(self._collection, trace_filter)


    def distinct(self, column):
        """
        Count the number of distinct fields in the currently selected MongoDB
        collection's specified column.

        :param str field: name of the column for counting distinct addresses.
        :returns: the number of packets matching the filter in the currently
            selected collection.
        """

        return self.__db.distinct_packets(self._collection, column)


    def retrieve(self, trace_filter={}, limit=0):
        """
        Retrieve packets from the currently selected MongoDB collection into
        memory, decoding base64-encoded payload and TLS data where possible.

        :param dict trace_filter: a MongoDB query filter, can be empty -- in which
            case all packets returned.
        :param int limit: a positive integer containing the maximum number of packets
            to retrieve (normally in time-ascending order), or 0 for unlimited.
        :returns: List of packets as specified. Returns an empty list of packets
            if no collection is selected or filter invalid.
        """

        if isinstance(limit, int) and limit > 0:
            max_r = limit
        else:
            max_r = 0

        try:
            packets = self.__db.find_packets(self._collection, trace_filter, max_r)
        except MemoryError:
            print("Warning: cannot allocate sufficient memory for packets, perhaps you are using Windows?")
            return []
        except:
            return []

        # Attempt to decode base64 payloads.
        for packet in packets:
            if packet["tcp_info"] is not None:
                if isinstance(packet["tcp_info"]["payload"], bytes):
                    try:
                        packet["tcp_info"]["payload"] = b64decode(packet["tcp_info"]["payload"])
                    except:
                        continue

            if packet["tls_info"] is not None:
                for i, data in enumerate(packet["tls_info"]["data"]):
                    if isinstance(data, bytes):
                        try:
                            packet["tls_info"]["data"][i] = b64decode(data)
                        except:
                            continue

        return packets
