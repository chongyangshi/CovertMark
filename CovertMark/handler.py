import data, analytics, strategy
import constants as c
import utils

import os, sys
from tabulate import tabulate


class Commands:
    cs = {}
    hs = {}
    @classmethod
    def register(cls, help_text):
        def decorator(func):
            cls.cs[func.__name__] = func
            cls.hs[func.__name__] = help_text
            return func
        return decorator


class CommandHandler:

    def __init__(self, strategy_map):

        # Access facilities.
        self.__db = data.mongo.MongoClient()
        self.__reader = data.retrieve.Retriever()
        self._strategy_map = strategy_map
        self._collections = self.__reader.list()

        # Handler states.
        self._current_procedure = []
        self._results = []


    def dispatch(self, command):
        """
        Dispatch a user command to the correct method.
        :param command: a top-level command matching the name of a handler method,
            with parameter gathering handled by the handler method itself.
        :returns: False if the command does not map to a handler method, True
            if otherwise handler successfully executed.
        """

        command = command.strip()
        if command not in Commands.cs:
            return False
        else:
            Commands.cs[command](self)

        return True


    @Commands.register("Display this help information.")
    def help(self):
        padding = len(max(Commands.cs, key=len)) + 1
        for command in Commands.cs:
            print(command.ljust(padding) + ": " + Commands.hs[command])
        print("")


    @Commands.register("List all available traces.")
    def traces(self):
        traces = self.__reader.list()
        traces_tabulate, _ = utils.list_traces(traces)
        print(traces_tabulate)


    @Commands.register("Load and execute an existing benchmark procedure in json.")
    def load(self):
        path = input("Enter the path to the procedure json: ").strip()
        procedure = utils.import_procedure(path, self._strategy_map)
        if not procedure:
            print(path + " does not seem to exist.")
        else:
            print("Procedure has been successfully loaded, executing...")
            results, new_procedure = utils.execute_procedure(procedure, self._strategy_map, db_sub=True)
            if len(results) > 0:
                replace = input("Do you wish to update PCAP and input filters with a local MongoDB copy? This will make the new procedure unportable [y/N]:")
                if replace.lower() == 'y':
                    self._current_procedure = new_procedure
                    print("Procedure settings replaced, save the procedure to apply the changes.")
                else:
                    self._current_procedure = procedure
                self._results.append(results)
            else:
                print("No strategy run has been successfully executed.")


    @Commands.register("Program a new benchmark procedure.")
    def new(self):

        print("Programming a new benchmark procedure.")
        procedure = []
        while True:
            print("List of available strategy runs: ")
            runs, indices = utils.get_strategy_runs(self._strategy_map)
            print(runs)

            while True:
                next_run = input("Enter a Run ID to configure a run, or enter `end` to finish: ").strip()
                if next_run == "end":
                    break
                try:
                    next_run = int(next_run)
                    if 0 <= next_run <= len(indices):
                        break
                except:
                    print("Invalid Run ID.")

            if next_run == "end":
                break

            # Strategy map should have already been validated during read.
            strat = self._strategy_map[indices[next_run][0]]
            run_info = [i for i in strat["runs"] if i["run_order"] == indices[next_run][1]][0]
            print("Adding {} on {}.".format(strat["object"], run_info["run_description"]))

            run = {'strategy': indices[next_run][0], 'run_order': indices[next_run][1]}

            # Get filter information.
            pt_filter_types = strat["pt_filters"]
            neg_filter_types = strat["negative_filters"]

            # See if we have matching traces already in the database.
            print(c.colours.BGC + c.colours.RED + "Configuring positive (PT) traffic for this run." + c.colours.ENDC)
            pts_in_db = self.__reader.list(in_string=False, match_filters=pt_filter_types)
            trace_id = ""
            if len(pts_in_db) > 0:
                pts_in_db, collections = utils.list_traces(pts_in_db)
                print("The following traces already in MongoDB can be used with this strategy run: ")
                print(pts_in_db)
                print(c.colours.BGC + c.colours.RED + "Check directions very carefully as the traces listed may have been imported for the opposite direction to this run, thus inappropriate to use." + c.colours.ENDC)
                print("If you choose to reuse an existing trace collection here, the procedure will not be portable between computers.")
                trace_id = input("Enter a trace ID to select and reuse as PT traffic, or enter nothing to skip and use a new PCAP: ").strip()

            try:
                trace_id = int(trace_id)
            except:
                trace_id = ""

            # Need to configure a new PCAP and its input filters.
            run['pt_filters'] = []
            run['pt_collection'] = ""
            run['pt_pcap'] = ""
            if not isinstance(trace_id, int) or trace_id not in collections:

                # Set PCAP.
                while True:
                    pt_pcap = input("Enter the path to the PCAP file containing PT traffic: ").strip()
                    if data.utils.check_file_exists(os.path.expanduser(pt_pcap)):
                        run["pt_pcap"] = pt_pcap
                        break
                    else:
                        print("The PCAP path entered does not seem to exist.")

                # Set input filters.
                if data.constants.IP_SRC in pt_filter_types:
                    while True:
                        clients = input("Enter IP addresses or subnets for clients using PT, separated by ',': ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['pt_filters'].append([i, data.constants.IP_SRC])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_EITHER in pt_filter_types:
                    while True:
                        clients = input("Enter IP addresses or subnets for clients or servers using PT under observation interest, separated by ',': ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['pt_filters'].append([i, data.constants.IP_EITHER])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_DST in pt_filter_types:
                    while True:
                        clients = input("Enter IP addresses or subnets for servers hosting PT bridges, separated by ',': ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['pt_filters'].append([i, data.constants.IP_DST])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

            # We can use an existing collection instead.
            else:
                run['pt_collection'] = collections[trace_id]

            # Now do the same for negative traffic.
            print(c.colours.BGC + c.colours.GREEN + "Configuring negative (innocent) validation traffic for this run." + c.colours.ENDC)
            negs_in_db = self.__reader.list(in_string=False, match_filters=neg_filter_types)
            trace_id = ""
            if len(negs_in_db) > 0:
                negs_in_db, collections = utils.list_traces(negs_in_db)
                print("The following traces already in MongoDB can be used with this strategy run: ")
                print(negs_in_db)
                print(c.colours.BGC + c.colours.GREEN + "Check directions very carefully as the traces listed may have been imported for the opposite direction to this run, thus inappropriate to use." + c.colours.ENDC)
                print("If you choose to reuse an existing trace collection here, the procedure will not be portable between computers.")
                trace_id = input("Enter a trace ID to select and reuse as negative traffic, or enter nothing to skip and use a new PCAP: ").strip()

            try:
                trace_id = int(trace_id)
            except:
                trace_id = ""

            # Need to configure a new PCAP and its input filters.
            run['neg_filters'] = []
            run['neg_collection'] = ""
            run["neg_pcap"] = ""
            if not isinstance(trace_id, int) or trace_id not in collections:

                # Set PCAP.
                while True:
                    neg_pcap = input("Enter the path to the PCAP file containing negative traffic: ").strip()
                    if data.utils.check_file_exists(os.path.expanduser(neg_pcap)):
                        run["neg_pcap"] = neg_pcap
                        break
                    else:
                        print("The PCAP path entered does not seem to exist.")

                # Set input filters.
                if data.constants.IP_SRC in neg_filter_types:
                    while True:
                        clients = input("Enter IP addresses or subnets for innocent clients in the PCAP, separated by ',': ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['neg_filters'].append([i, data.constants.IP_SRC])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_EITHER in neg_filter_types:
                    while True:
                        clients = input("Enter IP addresses or subnets for innocent clients or servers under observation interest, separated by ',': ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['neg_filters'].append([i, data.constants.IP_EITHER])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_DST in neg_filter_types:
                    while True:
                        clients = input("Enter IP addresses or subnets for primary innocent servers in the PCAP, separated by ',': ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['neg_filters'].append([i, data.constants.IP_DST])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

            # We can use an existing collection instead.
            else:
                run['neg_collection'] = collections[trace_id]

            run['user_params'] = []
            if len(run_info["user_params"]) > 0:
                for param in run_info["user_params"]:
                    while True:
                        val = input("Enter the {} value for runtime parameter `{}`: ".format(param[1].__name__, param[0])).strip()
                        try:
                            param_val = param[1](val)
                            run['user_params'].append([param[0], param_val])
                            break
                        except:
                            print("The value entered is invalid.")

            procedure.append(run)
            print("Strategy run has been successfully added to the current procedure.")

        self._current_procedure = procedure
        print(procedure)
