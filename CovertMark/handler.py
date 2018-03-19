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
        header = ('Description', 'Created', 'Stream Direction(s)', 'Packets')
        output = []
        for trace in traces:
            description = utils.width(trace['description'], 30)
            created = utils.width(trace['creation_time'], 10)
            directions = ""
            for f in trace["input_filters"]:
                if f[1] == data.constants.IP_SRC:
                    directions += "from    " + f[0] + '\n'
                elif f[1] == data.constants.IP_DST:
                    directions += "to      " + f[0] + '\n'
                else:
                    directions += "from/to " + f[0] + '\n'
            size = trace['count']
            output.append((description, created, directions, size))

        print(tabulate(output, header, tablefmt="fancy_grid"))
        print("IDs for selection will be available when programming a benchmark procedure.")


    @Commands.register("Load and execute an existing benchmark procedure in json.")
    def load(self):
        path = input("Enter the path to the procedure json: ").strip()
        procedure = utils.import_procedure(path, self._strategy_map)
        if not procedure:
            print(path + " does not seem to exist.")
        else:
            print("Procedure has been successfully loaded, executing...")
            utils.execute_procedure(procedure, self._strategy_map)


    
