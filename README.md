CovertMark
==================

**CovertMark** is a deep packet inspection (DPI) framework for evaluating and benchmarking the *covertness* of protocol-obfuscation proxies. Working from the perspective of a state censor with extensive computational resources, CovertMark performs automated passive analysis on captured proxy traffic to determine the likelihood and practicality of accurate protocol classification, which in turn allows the state censor to block such traffic. All TCP-based proxy protocols are applicable, including currently deployed [Tor pluggable transports](https://www.torproject.org/docs/pluggable-transports.html.en) and tunnelling proxies such as [shadowsocks](https://github.com/shadowsocks/shadowsocks/tree/master).

As an integrated offline traffic analysis solution, CovertMark is implemented entirely with Python, and beyond supplying standard tcpdump [PCAP](http://www.tcpdump.org/) files containing proxy traffic and clean traffic (for false positive evaluation), no pre- or post-processing in tools such as Wireshark or Bro are required. In addition to a summary report of covertness benchmarks (and a *CovertMark Score*), full CSV results and simple graph plotting are also available from CovertMark.

CovertMark comprises of generalised strategies (`CovertMark/strategy`) observing different features of traffic, with varying effects on different proxy protocols. You can easily implement new strategies into CovertMark by extending `CovertMark.strategy.strategy.DetectionStrategy`. For more detailed descriptions on how strategies can be implemented, please see the strategy implementation page [here](https:///).

Installation
======
CovertMark requires Python 3.5 or newer, which can be obtained from [python.org](https://www.python.org/downloads/) should your system came with an older version. For easy setup of dependencies, `setuptools` and `pip` are recommended, as well as `virtualenv`. These are normally available from your system's package management system, such as apt on Debian and Ubuntu, and brew on Mac OS X. They can otherwise be installed by downloading releases and installing manually with Python.

CovertMark uses a local MongoDB (3.2+) database to store parsed traffic traces for fast access, which can be installed by following the tutorial [here](https://docs.mongodb.com/manual/administration/install-community/). MongoDB authentication is supported locally (see the relevant section below).

In addition to UNIX and UNIX-like systems, CovertMark *should* work on Windows with all necessary dependencies, but the author did not have an appropriate machine to test it at the time of release.

On Debian and Ubuntu, `matplotlib` requires some additional dependencies:

    sudo apt-get install libbz2-dev tk-dev

These should have been included in Command Line Tools distributed with Apple's Xcode on Mac OS X.

To set up CovertMark itself:

    git clone https://github.com/icydoge/CovertMark.git

    cd CovertMark

    virtualenv env -p python3.5   # or python3.6, etc.

    source env/bin/activate

    pip install -r DEPENDENCIES

If your local MongoDB requires authentication, copy `/CovertMark/data/mongo-auth-example.json` into `/CovertMark/data/mongo-auth.json`, and edit the username, password, and authentication database required.

You can move your proxy PCAP files and regular (negative) traffic PCAP files into `/CovertMark/examples/local`, or leave it elsewhere on the system to specify an explicit path later. If you wish to use the *cantab* negative traces or any other example traces supplied by the project, please download them separately from [the data page here](https:///).

To run CovertMark's command line user interface, simply run `/CovertMark` in module mode:

    python -m CovertMark

In the command line interface, all possible commands (with parameters collected within) can be shown by entering `help`:

    CovertMark >>> help

Operations and Usage
======

While the command line interface should be sufficiently intuitive, it is necessary to first explain how the covertness benchmarking works in CovertMark.

A Game of Filters
------

Filters nearly always become the most irritating part of any network traffic analysis system, as it is necessary to avoid processing wrong types of packets. CovertMark uses two types of filters, only one of which need to be manipulated by the user (the other by strategy designers only).

The user-facing *input filters* determine what IP addresses or subnets, as well as what direction(s) of flow should be parsed from the PCAP file into MongoDB for further analysis. Not all strategies require both directions of flow, and this will be automatically handled by CovertMark rather than the user, based on the strategy designer's specifications. CovertMark also supports IPv4 and IPv6 (mutually without much engineering effort thanks to Python 3's `ipaddress` library).

Therefore for the user, it is only necessary to know what IP addresses (e.g. 192.168.0.42, 2001:db8:a0b:12f0::1) or subnets (192.168.0.0/24, 2001:db8:a0b:12f0::/64) are to be associated with the clients and (if applicable) proxy servers in the PCAP files. These information will be prompted when setting up a CovertMark procedure from the user interface. Multiple clients and proxy servers are supported, which can be entered as a subnet if they are the only members of that subnet in the PCAP, or as distinct IP addresses separated by a comma.

Once the PCAP files are parsed into MongoDB, these information will be carried within a collection of parsed traces, and will not be required again from the user until manual deletion.

The other type of filters  (relevant only to strategy designers) are *strategic filters*, which specify the inclusion of only certain types of packets for examination (e.g. TCP packets with payload but no TLS record), and are strategy-specific. Packets not matching the strategic filter will remain in MongoDB (to enable shared use between strategies to save disk space) but not loaded by the strategy who does not need it (to improve performance).

A Clash of Strategies
------

In order to streamline the benchmarking process to reduce manual configuration efforts, *procedures* are used to represent a series of strategy executions (*runs*) on the same or different inputs from PCAP files or MongoDB-stored traces. A strategy can have multiple runs to, for example, perform identical computations separately on both client-to-server and server-to-client packets.

A Storm of Procedures
------

To set up a procedure in the command line interface:

    CovertMark >>> new

The interface will then prompt you to choose from possible runs of strategies; choose to import PCAP files or to select from existing MongoDB-stored traces; specify input filters as necessary; and supply additional runtime parameters required by the strategy run. This process will be repeated until you have set up all the runs of strategies you need, and allows duplications of runs should you wish to test the same run on different inputs. This will replace whatever procedure already set up or loaded.

You can view MongoDB-stored traces from past executions with `traces`, and delete some as required with `delete` if freeing up some disk space is needed.

Once you have set up your procedure, you can `save` it to a JSON file now, or delay saving until after the procedure's execution to use the parsed traces in MongoDB instead next time.

    CovertMark >> save

To load a saved procedure, enter `load` and specify when prompted a relative or full path to where the procedure is stored as a JSON file.

At any time, you can check the current procedure in use by entering `current`. Once you are ready to execute the CovertMark procedure, enter `execute` to start the automated process.

The rest of the interface commands become available after results have been yielded from the execution of runs. Results include true positive rates (TPRs), false positive rates (FPRs), execution times on positive traces, and percentage of remote IPs falsely blocked in negative traces; corresponding to different configurations (one or more parameters) embedded within each strategy.

To view a list of results available, enter `results`. These will be retained until CovertMark exits, unless deleted with `delresults`. Falsely blocked remote IPs can be inspected in Wireshark with a generated display filter, which can be obtained through the `wireshark` command.

Assuming all runs of strategies in your procedure are on traces from the same proxy or pluggable transport protocol, you can view a summative report of the covertness of that protocol and its CovertMark Score by entering:

    CovertMark >>> score

You can export full results of strategy runs by entering `csv`, which will export CSV records of all current results into a directory specified. Simple plotting between strategy configuration parameters and performance metrics can be done in `plot`, which will prompt the specific parameter(s) and metric(s) you wish to plot in pairs. More complex plots can be done separately from the CSVs exported.

Publication(s)
======

This project is the resulting product of my MPhil thesis *Covertness benchmarking of Tor pluggable transports* at the Computer Laboratory of the University of Cambridge, which will likely become a technical report and/or (hopefully) a conference paper. Citations to the relevant publication(s) will be available here once progresses have been made in publication.

Problems and Feedback
======

Despite extensive efforts made to engineer CovertMark as a user-facing product, it is likely to malfunction if not used in the intended ways. (For example, exceptions when supplied with PCAP files not matching the input filter, which are *very* difficult to check without consuming long execution times to read the PCAP first). If you do get strange or unexpected results after execution, it is worth checking whether the input filters have been entered correctly and match those in the PCAP files.

Of course, issues, pull requests, and general feedbacks are very welcome via the [GitHub repository](https://github.com/icydoge/CovertMark).
