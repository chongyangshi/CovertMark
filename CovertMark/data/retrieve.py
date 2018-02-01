from data import utils, constants, mongo

from base64 import b64decode

class Retriever:

    def __init__(self):
        self.__db = mongo.MongoDBManager(db_server=constants.MONGODB_SERVER)
        self._collection = None


    def list(self, in_string=False):
        """
        Return a list of all collections of traces currently stored in MongoDB.
        :param in_string: Pre-format the output in string if True.
        :returns: list of traces with {name, creation_time, description}.
        """

        traces = self.__db.list_collections()

        if not in_string:
            return traces

        output = "Available collections of traces:\n"

        for trace in traces:
            output += trace["name"] + ", " + trace["description"] + ", " + trace["creation_time"]

        return output


    def select(self, collection_name):
        """
        Set the retriever to the collection as specified, returns False if
        specified collection does not exist or invalid.
        :param: collection_name: the name of collection to be retrieved.
        :returns: True if successfully selected, False otherwise.
        """

        if self.__db.lookup_collection(collection_name):

            self._collection = collection_name
            return True

        else:
            return False


    def current(self):
        """
        :returns: the current collection of traces selected. None if none selected.
        """

        return self._collection


    def count(self, trace_filter={}):
        """
        Count the number of traces in the currently selected MongoDB collection,
        :param trace_filter: dictionary containing a MongoDB query filter, can
            be empty, in which case all traces counted.
        :returns: the number of traces matching the filter in the currently
            selected collection. False if invalid filter or no collection
            selected.
        """

        return self.__db.count_traces(self._collection, trace_filter)




    def retrieve(self, trace_filter={}, limit=0):
        """
        Retrieve traces from the currently selected MongoDB collection into
        memory, decoding base64-encoded payload and TLS data where possible.
        :param trace_filter: a dictionary containing a MongoDB query filter, can
            be empty, in which case all traces returned.
        :param limit: a positive integer containing the maximum number of traces
            to retrieve (normally in time-ascending order), or 0 for unlimited.
        :returns: List of traces as specified. Returns an empty list of traces
            if no collection is selected or filter invalid.
        """

        if isinstance(limit, int) and limit > 0:
            max_r = limit
        else:
            max_r = 0

        try:
            traces = self.__db.find_traces(self._collection, trace_filter, max_r)
        except:
            return []

        # Attempt to decode base64 payloads.
        for trace in traces:
            if trace["tcp_info"] is not None:
                if isinstance(trace["tcp_info"]["payload"], bytes):
                    try:
                        trace["tcp_info"]["payload"] = b64decode(trace["tcp_info"]["payload"])
                    except:
                        continue

            if trace["tls_info"] is not None:
                for i, data in enumerate(trace["tls_info"]["data"]):
                    if isinstance(data, bytes):
                        try:
                            trace["tls_info"]["data"][i] = b64decode(data)
                        except:
                            continue

        return traces
