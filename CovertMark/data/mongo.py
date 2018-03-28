from . import constants, utils, parser

from pymongo import MongoClient
import hashlib
from os import urandom, path
from datetime import date, datetime

class MongoDBManager:
    ''' A manager for the MongoDB used to store trace data, both for temporary
        working and long term storage, as demanded.
    '''

    def __init__(self, db_server=constants.MONGODB_SERVER):

        creds = utils.read_mongo_credentials()
        try:
            if creds is not None:
                self.__db_client = MongoClient(db_server, username=creds['username'],
                 password=creds['password'], authSource=creds['auth_source'],
                 serverSelectionTimeoutMS=500)
            else:
                self.__db_client = MongoClient(db_server, serverSelectionTimeoutMS=500)
            self.__db_client.server_info()
        except:
            print("Error: Cannot connect to MongoDB Server, please check whether MongoDB Server is running and auth credentials if set.")
            raise

        self.__db = self.__db_client['covertmark']
        self._trace_index = self.__db["trace_index"]


    def lookup_collection(self, collection_name):
        """
        Check whether a collection by the name exists in MongoDB.

        :param str collection_name: the name of collection checked.
        :returns: True if collection name exists, False otherwise.
        """

        if not collection_name:
            return False

        if not collection_name.isalnum():
            return False

        # Check whether collection is in the index.
        in_index = self._trace_index.find_one({"name": collection_name})

        # Check whether the collection exists in the database.
        in_db = collection_name in self.__db.collection_names()

        if in_index and in_db:
            return True

        # Inconsistency:
        # If in index but not in database, delete the index and return False.
        if in_index and not in_db:
            self._trace_index.delete_many({"name": collection_name})
            return False

        return False


    def new_collection(self, description="", input_filters=[]):
        """
        Create a new trace collection with a name, store and return it.

        :param str description: a description of this trace collection, empty by
            default.
        :param list input_filters: list of tuples (string-format filters, direction)
            for input filters of this collection.
        :returns: the name of the new collection.
        """

        collection_name = MongoDBManager.generate_name()

        # In case of collision.
        while self.lookup_collection(collection_name):
            collection_name = MongoDBManager.generate_name()

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check filters.
        for input_filter in input_filters:
            if not utils.build_subnet(input_filter[0]) or \
             input_filter[1] not in [constants.IP_SRC, constants.IP_DST, constants.IP_EITHER]:
                return False

        input_filters = [(str(i[0]), int(i[1])) for i in input_filters]

        new_c = {"name": collection_name, "creation_time": now,
            "description": description, "input_filters": input_filters}

        self.__db[collection_name]
        # Does not actually create the database due to MongoDB laziness.

        if self._trace_index.insert_one(new_c):
            return collection_name
        else:
            return False


    def delete_collection(self, collection_name):
        """
        Delete the index and the trace collection associated with collection_name.

        :param str collection_name: the name of the collection to be deleted.
        :returns: True if deleted where appropriate, False otherwise.
        """

        if not self.lookup_collection(collection_name):
            return False

        self._trace_index.delete_many({"name": collection_name})
        self.__db[collection_name].drop()

        return True


    def modify_collection_description(self, collection_name, description):
        """
        Modify the description of a trace collection.

        :param str collection_name: the name of the collection to be modified.
        :param str description: the new description of the collection.
        :returns: True if modification successful, False otherwise.
        """

        if not self.lookup_collection(collection_name):
            return False

        update_result = self._trace_index.update_one({"name": collection_name}, {'$set': {"description": description}})

        if update_result.modified_count > 0:
            return True
        else:
            return False


    def list_collections(self):
        """
        Return all valid collections.

        :returns: a list of valid collections with attributes.
        """

        collections = self._trace_index.find(projection={'_id': False})
        in_db_collections = self.__db.collection_names()
        valid_collections = []
        for collection in collections:
            if collection["name"] in in_db_collections:
                valid_collections.append(collection)

        return valid_collections


    def insert_traces(self, traces, collection_name=""):
        """
        Insert a list of fomatted packet traces. Should be used only by
        :meth:`parser.PCAPParser.load_packet_info`, as format checking is not done
        here.

        :param list traces: see docstring of that function for input format.
        :param str collection_name: The name of the collection to be inserted into,
            create a new collection with random name if unspecified.
        :returns: dict containing collection name and inserted count if insertion
            successful, False otherwise.
        """

        # Create new collection if supplied collection name does not exist.
        if collection_name == "":
            collection_name = self.new_collection()
            if not collection_name:
                return False
        # Otherwise, insertion can proceed no matter whether the collection
        # specified already exists, as it's insert or append by default.

        # Conduct the insertion.
        collection = self.__db[collection_name]
        inserted = collection.insert_many(traces)

        result = {"collection_name": collection_name, "inserted": inserted}

        return result


    def find_traces(self, collection_name, query_params, max_r=0):
        """
        Return matched packet traces in the named collection up to a max of max_r
        traces.

        :param str collection_name: name of the queried collection.
        :param dict query_params: query written in MongoDB query object format.
        :param int max_r: maximum number of returned traces, <= 0 means unlimited.
        :returns: traces found matching the query parameters.
        """

        if not self.lookup_collection(collection_name):
            return False

        if not isinstance(max_r, int) or max_r <= 0:
            max_r = False

        collection = self.__db[collection_name]
        if max_r:
            query_result = collection.find(filter=query_params, projection={'_id': False},
                limit = max_r)
        else:
            query_result = collection.find(filter=query_params, projection={'_id': False})

        result = [x for x in query_result]

        return result


    def count_traces(self, collection_name, query_params={}):
        """
        Return the number of query-matched packet traces in the named collection.

        :param str collection_name: name of the queried collection.
        :param dict query_params: query written in MongoDB query object format.
        :returns: the number of traces found matching the query parameters.
        """

        if not self.lookup_collection(collection_name):
            return False

        collection = self.__db[collection_name]
        query_count = collection.find(filter=query_params).count()

        return query_count


    def distinct_traces(self, collection_name, field_name):
        """
        Return the number of distinct fields of a column in the named collection.

        :param str collection_name: name of the queried collection.
        :param str field_name: name of column to count distinct traces.
        :returns: the number of distinct fields found.
        """

        if not self.lookup_collection(collection_name):
            return False

        collection = self.__db[collection_name]
        distinct_count = len(collection.find(filter={field_name: {"$ne": None}}).distinct(field_name))

        return distinct_count


    def delete_traces(self, collection_name, query_params):
        """
        Delete matched packet traces in the named collection.

        :param str collection_name: name of the queried collection.
        :param str query_params: query written in MongoDB query object format.
        :returns: traces deleted matching the query parameters.
        """

        if not self.lookup_collection(collection_name):
            return False

        collection = self.__db[collection_name]
        deletion_result = collection.delete_many(query_params)

        return deletion_result.deleted_count


    @staticmethod
    def generate_name():
        """
        Generate a trace collection name in the format of 'traces(yyyymmdd)random-hex-string'.

        :returns: a random collection name.
        """
        today = date.today().strftime("%Y%m%d")

        return "traces" + today + hashlib.sha1(urandom(8)).hexdigest()


    @staticmethod
    def log_error(error_content):
        """
        Utility function to log database errors.
        """
        if constants.LOG_ERROR and path.isfile(constants.LOG_FILE):
            with open(constants.LOG_FILE, "a") as log_file:
                log_file.write(error_content)
