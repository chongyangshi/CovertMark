from data import constants, utils

from pymongo import MongoClient
import hashlib
from os import urandom
from datetime import date, datetime

class MongoDBManager:
    ''' A manager for the MongoDB used to store trace data, both for temporary
        working and long term storage, as demanded.
    '''

    def __init__(self, db_server=constants.MONGODB_SERVER):

        try:
            self.__db_client = MongoClient(db_server, serverSelectionTimeoutMS=500)
            self.__db_client.server_info()
        except pymongo.errors.ServerSelectionTimeoutError as err:
            print("Error: Cannot connect to MongoDB Server, please check whether MongoDB Server is running.")
            raise

        self.__db = self.__db_client['covertmark']
        self._trace_index = self.__db["trace_index"]


    def lookup_collection(self, collection_name):
        """
        Check whether a collection by the name exists in MongoDB.
        :param collection_name: the name of collection checked.
        :returns: Boolean True if collection name exists, False otherwise.
        """

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


    def new_collection(self, description=""):
        """
        Create a new trace collection with a name, store and return it.
        :param description: a description of this trace collection, empty by default.
        :returns: the name of the new collection.
        """

        collection_name = MongoDBManager.generate_name()

        # In case of collision.
        while self.lookup_collection(collection_name):
            collection_name = MongoDBManager.generate_name()

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        new_c = {"name": collection_name, "creation_time": now,
            "description": description}

        self.__db[collection_name]
        # Does not actually create the database due to MongoDB laziness.

        if self._trace_index.insert_one(new_c):
            return collection_name
        else:
            return False


    def delete_collection(self, collection_name):
        """
        Delete the index and the trace collection associated with collection_name.
        :param collection_name: the name of the collection to be deleted.
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
        :param collection_name: the name of the collection to be modified.
        :param description: the new description of the collection.
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
        Insert a list of fomatted packet traces. ONLY to be called by
        data.parser.PCAPParser.load_packet_info, as format checking not done here.
        :param traces: see docstring of that function for input format.
        :param collection_name: The name of the collection to be inserted into,
            create a new collection with random name if unspecified.
        :returns: dict containing collection name and inserted count if insertion
            successful, False otherwise.
        """

        # Create new collection if supplied collection name does not exist.
        if collection_name == "":
            collection_name = self.new_collection()
            if not collection_name:
                return False
        else:
            # If a collection name is specified but does not exist, return False.
            if not self.lookup_collection(collection_name):
                return False

        # Conduct the insertion.
        collection = self.__db[collection_name]
        inserted = collection.insert_many(traces)

        result = {"collection_name": collection_name, "inserted": inserted}

        return result


    def find_traces(self, collection_name, query_params, max_r=0):
        """
        Return matched packet traces in the named collection up to a max of max_r
         traces.
        :param collection_name: name of the queried collection.
        :param query_params: query written in MongoDB query object format.
        :param max_r: maximum number of returned traces, <= 0 means unlimited.
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
        :param collection_name: name of the queried collection.
        :param query_params: query written in MongoDB query object format.
        :returns: number of traces found matching the query parameters.
        """

        if not self.lookup_collection(collection_name):
            return False

        collection = self.__db[collection_name]
        query_count = collection.find(filter=query_params).count()

        return query_count


    def delete_traces(self, collection_name, query_params):
        """
        Delete matched packet traces in the named collection.
        :param collection_name: name of the queried collection.
        :param query_params: query written in MongoDB query object format.
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
        :returns: None
        """
        if constants.LOG_ERROR and isfile(constants.LOG_FILE):
            with open(constants.LOG_FILE, "a") as log_file:
                log_file.write(error_content)
