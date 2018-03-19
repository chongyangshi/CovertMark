import data, analytics, strategy
import constants as c
import utils

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
        # Store previous inputs to save the user's time.
        previous_pt = []
        previous_neg = []

        print("Programming a new benchmark procedure.)
        while True:
            print("List of available strategy runs: ")
            runs, indices = utils.get_strategy_runs(self._strategy_map)

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

            run_strategy = indices[next_run][0]
            run_strat_order = indices[next_run][1]
