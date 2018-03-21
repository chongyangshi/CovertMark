import data, analytics, strategy
import constants as c
import utils

import os, sys
from tabulate import tabulate
from operator import itemgetter
from tempfile import gettempdir
from collections import defaultdict
from itertools import product


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
        self.__db = data.mongo.MongoDBManager()
        self.__reader = data.retrieve.Retriever()
        self._strategy_map = strategy_map
        self._collections = self.__reader.list()

        # Handler states.
        self._current_procedure = []
        self._results = {}
        self.__result_counter = 0
        self._imported_path = ""


    def dispatch(self, command):
        """
        Dispatch a user command or a sequence of commands to the correct methods.
        :param command: a top-level command matching the name of a handler method,
            with parameter gathering handled by the handler method itself. This
            can also be a sequence of commands separated by ";".
        :returns: False if the command does not map to a handler method, True
            if otherwise handler successfully executed.
        """

        command = command.strip()
        if command not in Commands.cs:
            command_seq = [i.strip() for i in command.split(";")]
            if all([i in Commands.cs for i in command_seq]):
                for cmd in command_seq:
                    Commands.cs[cmd](self)
            else:
                return False
        else:
            Commands.cs[command](self)

        return True


    @Commands.register("Exit this program.")
    def exit(self):
        # Handled by the calling module.
        return


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


    @Commands.register("Select and delete traces.")
    def delete(self):
        traces = self.__reader.list()
        traces_tabulate, names = utils.list_traces(traces)
        print("The following traces are currently stored in MongoDB, which were imported during strategy runs.")
        print("Deleting them will make procedures files referencing MongoDB collections only unusuable.")
        print(traces_tabulate)
        while True:
            deletes = input("Enter a Trace ID or a list of IDs (separated by ',') for deletion, or `end` to finish: ").strip()
            if deletes == "end":
                break
            deletes = [i.strip() for i in deletes.split(',')]

            if all([i.isdigit() for i in deletes]):
                deletes = [int(i) for i in deletes]
            else:
                print("Contains invalid IDs, not deleting.")
                continue

            if all([i in names for i in deletes]):
                confirm = input("Are you sure to delete {} trace collections? [y/N]:".format(len(deletes)))
                if confirm.lower() == 'y':
                    for i in deletes:
                        self.__db.delete_collection(names[i])
                    print("Deletion successful.")
                else:
                    print("Deletion cancelled.")
                break


    @Commands.register("Load and execute an existing benchmark procedure in json.")
    def load(self):
        path = input("Enter the path to the procedure json: ").strip()
        procedure = utils.import_procedure(path, self._strategy_map)
        if not procedure:
            print(path + " does not seem to exist or is invalid.")
        else:
            self._current_procedure = procedure
            print("Procedure has been successfully loaded, enter `execute` to run it.")
            self._imported_path = path


    @Commands.register("Program a new benchmark procedure to replace the current procedure.")
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
            use_negative = strat["negative_input"]
            print("Adding {} on {}.".format(strat["object"], run_info["run_description"]))

            run = {'strategy': indices[next_run][0], 'run_order': indices[next_run][1]}

            # Get filter information.
            pt_filter_types = strat["pt_filters"]
            if run_info["pt_filters_reverse"]:
                pt_filter_types = [strategy.constants.FILTERS_REVERSE_MAP[i] for i in pt_filter_types]
            neg_filter_types = strat["negative_filters"]
            if run_info["negative_filters_reverse"]:
                neg_filter_types = [strategy.constants.FILTERS_REVERSE_MAP[i] for i in neg_filter_types]

            # See if we have matching traces already in the database.
            print()
            print(c.colours.BGC + c.colours.RED + "Configuring positive (PT) traffic for this run." + c.colours.ENDC)
            pts_in_db = self.__reader.list(in_string=False, match_filters=pt_filter_types)
            trace_id = ""
            if len(pts_in_db) > 0:
                pts_in_db, collections = utils.list_traces(pts_in_db)
                print("The following traces already in MongoDB can be used with this strategy run: ")
                print(pts_in_db)
                print(c.colours.BGC + c.colours.RED + "Check directions very carefully, as the traces listed may have been imported for the opposite direction to this run, thus inappropriate to use." + c.colours.ENDC)
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
                print("Collecting PT IP filters for importing the PCAP, please enter IPv4/IPv6 addresses or subnets separated by ',':")
                if data.constants.IP_SRC in pt_filter_types:
                    while True:
                        clients = input("Who are the PT clients: ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['pt_filters'].append([i, data.constants.IP_SRC])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_EITHER in pt_filter_types:
                    while True:
                        clients = input("Observe traffic in both directions passing through: ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['pt_filters'].append([i, data.constants.IP_EITHER])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_DST in pt_filter_types:
                    while True:
                        clients = input("Who are the PT bridge servers: ").split(",")
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
            print()
            print(c.colours.BGC + c.colours.GREEN + "Configuring negative (innocent) validation traffic for this run." + c.colours.ENDC)
            negs_in_db = self.__reader.list(in_string=False, match_filters=neg_filter_types)
            trace_id = ""
            if use_negative and len(negs_in_db) > 0:
                negs_in_db, collections = utils.list_traces(negs_in_db)
                print("The following traces already in MongoDB can be used with this strategy run: ")
                print(negs_in_db)
                print(c.colours.BGC + c.colours.GREEN + "Check directions very carefully, as the traces listed may have been imported for the opposite direction to this run, thus inappropriate to use." + c.colours.ENDC)
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
            if use_negative and (not isinstance(trace_id, int) or trace_id not in collections):

                # Set PCAP.
                while True:
                    neg_pcap = input("Enter the path to the PCAP file containing negative traffic: ").strip()
                    if data.utils.check_file_exists(os.path.expanduser(neg_pcap)):
                        run["neg_pcap"] = neg_pcap
                        break
                    else:
                        print("The PCAP path entered does not seem to exist.")

                # Set input filters.
                print("Collecting negative IP filters for importing the PCAP, please enter IPv4/IPv6 addresses or subnets separated by ',':")
                if data.constants.IP_SRC in neg_filter_types:
                    while True:
                        clients = input("Who are the innocent clients under suspicion: ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['neg_filters'].append([i, data.constants.IP_SRC])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_EITHER in neg_filter_types:
                    while True:
                        clients = input("Observe traffic in both directions passing through: ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['neg_filters'].append([i, data.constants.IP_EITHER])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

                if data.constants.IP_DST in neg_filter_types:
                    while True:
                        clients = input("Who are the innocent servers under suspicion: ").split(",")
                        clients = [i.strip() for i in clients]
                        if all([data.utils.build_subnet(i) for i in clients]):
                            for i in clients:
                                run['neg_filters'].append([i, data.constants.IP_DST])
                            break
                        else:
                            print("Some addresses or subnets entered are invalid.")

            # We can use an existing collection instead.
            elif use_negative:
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

        if len(procedure) > 0:
            self._current_procedure = procedure
            print("Procedure successfully created, enter `execute` to run it.")
        else:
            print("No strategy run has been programmed into the procedure, abandoning it.")


    @Commands.register("Display the current procedure.")
    def current(self):
        print(utils.printable_procedure(self._current_procedure, self._strategy_map))


    @Commands.register("Execute the current procedure.")
    def execute(self):

        if len(self._current_procedure) == 0 or not utils.validate_procedure(self._current_procedure, self._strategy_map):
            print("There is no valid procedure loaded, enter `new` to create a new procedure.")
            return

        results, new_procedure = utils.execute_procedure(self._current_procedure, self._strategy_map, db_sub=True)
        print("Execution of the current procedure is complete.")
        if len(results) > 0:
            # Check if there were any non-collection inputs.
            original_procedure_has_explicit_inputs = False
            for run in self._current_procedure:
                if run["pt_collection"] == "" or run["neg_collection"] == "":
                    original_procedure_has_explicit_inputs = True
                    break

            # If so, ask the user whether they want to replace it.
            if original_procedure_has_explicit_inputs:
                replace = input("Do you wish to use the MongoDB copy/copies instead of the PCAP(s) from now on? This will make the new procedure faster but unportable [y/N]:")
                if replace.lower() == 'y':
                    self._current_procedure = new_procedure
                    print("Procedure settings replaced, `save` the procedure to file to permanently apply the changes.")
            for result in results:
                self._results[self.__result_counter] = [result[1]["strategy"], result[1]["run_order"], result[0]]
                self.__result_counter += 1
        else:
            print("No strategy run has been successfully executed.")


    @Commands.register("Save the current procedure to file.")
    def save(self):

        if len(self._current_procedure) == 0 or not utils.validate_procedure(self._current_procedure, self._strategy_map):
            print("There is no valid procedure loaded, enter `new` to create a new procedure.")
            return

        while True:
            if self._imported_path != "":
                path_prompt = "Enter the export path for the procedure [" + self._imported_path + "]: "
            else:
                path_prompt = "Enter the export path for the procedure (e.g. ~/Documents/covertmark.json): "
            out_path = input(path_prompt).strip()

            if out_path == "cancel":
                break

            if self._imported_path != "" and out_path == "":
                out_path = self._imported_path

            if utils.save_procedure(out_path, self._current_procedure, self._strategy_map):
                print("Successfully saved current procedure to " + out_path + ".")
                break
            else:
                print("Unable to save current procedure due to invalid output path or a permissions issue.")


    @Commands.register("List results from strategy runs in this session.")
    def results(self):

        if len(self._results) == 0:
            print("There are no results yet, enter `execute` to run the current procedure for results.")
            return

        print(utils.printable_results(self._results, self._strategy_map))


    @Commands.register("Clear the currently stored results.")
    def delresults(self):

        confirm = input("Are you sure you want to delete all results in this session? [y/N]:").strip()
        if confirm.lower() == "y":
            self._results = {}
            print("Deletion successful.")
        else:
            print("Deletion abandoned.")


    @Commands.register("Get the Wireshark display filters for a result.")
    def wireshark(self):

        if len(self._results) == 0:
            print("There are no results yet, enter `execute` to run the current procedure for results.")
            return

        print("Available results:")
        print(utils.printable_results(self._results, self._strategy_map))

        while True:
            try:
                result = input("Enter result ID to view its falsely blocked IPs' Wireshark display filter (`end` to quit): ").strip()
                if result == "end":
                    break
                else:
                    result = int(result)
                if result not in self._results:
                    raise ValueError()
            except:
                print("Invalid result ID.")
                continue

            print(self._results[result][2].report_blocked_ips())
            print()


    @Commands.register("Compute CovertMark scores for the current results.")
    def score(self):

        if len(self._results) == 0:
            print("There are no results yet, enter `execute` to run the current procedure for results.")
            return

        print("Available results:")
        print(utils.printable_results(self._results, self._strategy_map))
        print("The overall score will assume that all these results are for the same PT protocol involved.")
        print()

        results = {}
        for n, result in self._results.items():
            score, config = result[2]._score_performance_stats()
            results[n] = {}

            if 0 <= score <= 100:
                for r in c.RATINGS:
                    if r[0] <= score < r[1]:
                        attrs = c.RATINGS[r]
                        results[n]["colour"] = attrs[0]
                        results[n]["explanation"] = attrs[1]
                        break

                results[n]["score"] = round(score, 2)
                results[n]["config"] = result[2].interpret_config(config)

                results[n]["strategy_name"] = result[2].NAME
                results[n]["run_description"] = [i for i in self._strategy_map[result[0]]["runs"] if i["run_order"] == result[1]][0]["run_description"]

        results = sorted(results.items(), key=lambda x: x[1]["score"])
        # The lower the score, the better the protocol. Therefore ascending.

        print(c.CM_NAME + " Report:")
        # Tabulate is funky with spaces when ANSI colour is involved, therefore not used.
        for _, result in results:
            print("-"*80)
            print(result["colour"] + str(result["score"]) + c.colours.ENDC + " from " +\
             result["strategy_name"] + " | " + result["run_description"])
            print(c.colours.BOLD + result["explanation"] + c.colours.ENDC)
            print("Best strategy configuration: " + result["config"])
            print("-"*80)

        overall_score = results[0][1]["score"]
        overall_colour = results[0][1]["colour"]
        overall_band = ""
        for r in c.RATING_BANDS:
            if r[0] <= score < r[1]:
                overall_band = c.RATING_BANDS[r]
                break

        print("Overall rating: " + overall_colour + overall_band + c.colours.ENDC)
        print("The overall rating is determined by its weakest performance among all benchmark strategies.")


    @Commands.register("Generate and export full CSVs of results.")
    def csv(self):

        if len(self._results) == 0:
            print("There are no results yet, enter `execute` to run the current procedure for results.")
            return

        default_path = "~/Documents/"
        out_path = input("Enter the directory for CSVs to be saved to [" + default_path + "]: ").strip()
        if out_path == "":
            out_path = default_path

        if not os.path.isdir(os.path.expanduser(out_path)):
            print("Invalid path.")
            return

        written = utils.save_csvs(self._results, out_path)

        if len(written) == len(self._results):
            print("All CSVs have been successfully written to " + out_path + ".")
        elif len(written) < len(self._results) and len(written) > 0:
            print("Some CSVs have been successfully written to " + out_path + ", but others failed.")
        else:
            print("Could not write the CSVs to " + out_path + ", check for strategy execution errors and permissions.")


    @Commands.register("Select and plot data from results.")
    def plot(self):

        if len(self._results) == 0:
            print("There are no results yet, enter `execute` to run the current procedure for results.")
            return

        # Get destination of the plots first.
        default_path = "~/Documents/"
        out_path = input("Enter the directory for plots to be saved to [" + default_path + "]: ").strip()
        if out_path == "":
            out_path = default_path

        if not os.path.isdir(os.path.expanduser(out_path)):
            print("Invalid path.")
            return

        # Save the CSVs to a temporary location by saving single CSVs.
        temp_dir = os.path.join(gettempdir(), utils.random_file_name(c.CM_NAME, "csvs"))
        os.makedirs(temp_dir)
        csvs = {i: utils.save_csvs({i: self._results[i]}, temp_dir)[0] for i in self._results}
        csv_headers = {i: self._results[i][2].make_csv().splitlines()[0] for i in self._results}

        # Extract the attributes available for plotting.
        y_keys = list(strategy.constants.TIME_STATS_DESCRIPTIONS.keys())
        y_values = list(strategy.constants.TIME_STATS_DESCRIPTIONS.values())
        attributes = defaultdict(list)
        for i, header in csv_headers.items():
            attrs = [x.strip() for x in header.split(",")]
            for attr in attrs:
                if attr not in y_values:
                    attributes[attr].append(i)

        # Display the selection table.
        headers = ("ID", "Attribute", "Results From")
        contents = []
        attr_id = 0
        attr_id_to_attr = {}
        for attr, in_results in attributes.items():
            attribute_name = utils.width(attr, 25)
            results_names = utils.width(",".join(list(set([self._results[i][2].NAME for i in in_results]))), 30)
            contents.append((attr_id, attribute_name, results_names))
            attr_id_to_attr[attr_id] = attr
            attr_id += 1

        print("The following attributes are available on the x-axis of the plot:")
        print(tabulate(contents, headers, tablefmt="fancy_grid"))

        while True:
            x_attrs = input("Select a list of x-axis attribute IDs for plotting, separated by ',': ").strip()
            try:
                x_attrs = [int(i.strip()) for i in x_attrs.split(",")]
                if len(x_attrs) < 1:
                    raise ValueError()
                for x_attr in x_attrs:
                    if x_attr < 0 or x_attr >= attr_id:
                        raise ValueError()
                break
            except:
                print("Invalid attribute ID(s) were entered.")
        x_attrs_selected = [attr_id_to_attr[i] for i in x_attrs]

        print("The following attributes are available on the y-axis of the plot:")
        print(tabulate([(i, y_keys[i], y_values[i]) for i, _ in enumerate(y_keys)],
         ("ID", "Attribute Key", "Attribute Text"), tablefmt="fancy_grid"))
        y_id_to_y = {i: y_values[i] for i, _ in enumerate(y_keys)}
        # All strategies should have these information available after execution.

        while True:
            y_attrs = input("Select a list of y-axis attribute IDs for plotting, separated by ',': ").strip()
            try:
                y_attrs = [int(i.strip()) for i in y_attrs.split(",")]
                if len(y_attrs) < 1:
                    raise ValueError()
                for y_attr in y_attrs:
                    if y_attr < 0 or y_attr >= len(y_keys):
                        raise ValueError()
                break
            except:
                print("An invalid attribute ID was entered.")
        y_attrs_selected = [y_id_to_y[i] for i in y_attrs]

        plot_attrs = product(x_attrs_selected, y_attrs_selected)
        for plot_attr in plot_attrs:
            relevant_results = attributes[plot_attr[0]]
            relevant_csvs = [csvs[i] for i in relevant_results]
            out_file = os.path.join(out_path, utils.random_file_name(plot_attr[0] + "_" + plot_attr[1], "png"))
            out_file = out_file.replace(" ", "_")
            data.plot.plot_performance(relevant_csvs, ["unnamed" for i in relevant_csvs], plot_attr[0], plot_attr[1],
             show=False, img_out=out_file, title=plot_attr[1])
            print("Saving " + out_file + "...")
