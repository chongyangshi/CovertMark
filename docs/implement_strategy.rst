Implementing a new CovertMark strategy
======================================

CovertMark strategies exploit specific packet features to distinguish
protocol-obfuscation proxy traffic from standard traffic. Current
built-in strategies look at the uniformity and entropy distributions of
bytes in TCP payloads (:mod:`CovertMark.strategy.entropy_dist` from [1]);
and the estimations thereof (:mod:`CovertMark.strategy.entropy_est`); and
unusual densely-distributed TCP payload lengths that are either all TLS
or all non-TLS (:mod:`CovertMark.strategy.length_clustering`); and a
generalised traffic shaping approach training a SGD classifier that does
not rely on observing handshakes (:mod:`CovertMark.strategy.sgd`, improving
on the machine learning method in [1]).

While modules of existing strategies listed above serve as a very good
source of implementation reference for new strategies, it is also useful
to provide some general guidance on how they should be designed to
minimise re-implementation effort when integrating within CovertMark.

The :class:`~CovertMark.strategy.strategy.DetectionStrategy` Class
------------------------------------------------------------------------

The densely documented :class:`~CovertMark.strategy.strategy.DetectionStrategy` class performs most
housekeeping tasks to allow you to focus on implementing your detection
method instead. The last two hundred lines or so in
:mod:`CovertMark.strategy.strategy` contains the abstract and non-abstract
methods you should implement or override to integrate your detection
method with CovertMark, while other inheriting methods should suffice
for implementations of most detection methods – with a few quirks that
will be explained later.

**What is provided by the abstract strategy**

-  Parsing and storage of packets in PCAP files supplied by the user, or
   skipping this step if the user has supplied via the command line
   interface valid collections of MongoDB-stored packets. This is done
   by initialising the strategy class with optional paths to PCAP files
   and calling :meth:`~CovertMark.strategy.strategy.DetectionStrategy.setup` to supply input filters and/or existing
   collections.
-  Loading of parsed or stored packets into memory. Only packets
   matching the strategic filter you set in :meth:`~CovertMark.strategy.strategy.DetectionStrategy.set_strategic_filter`
   will be loaded by calling :mod:`~CovertMark.strategy.strategy.DetectionStrategy.load`.
-  Keeping note of what IP addresses or subnets are within the input
   filters for positive and negative traces respectively, allowing them
   to be labelled or queried by calling :meth:`~CovertMark.strategy.strategy.DetectionStrategy.in_positive_filter` and
   :meth:`~CovertMark.strategy.strategy.DetectionStrategy.in_negative_filter` as necessary.
-  Automatically timing the execution times of your strategy runs on
   positive packets, which form part of the CovertMark scoring scheme,
   as well as other performance metrics if correctly returned from
   positive and negative runs. You can manually record the TPR, FPR, and
   false positive IP block rates by calling
   :meth:`~CovertMark.strategy.strategy.DetectionStrategy.register_performance_stats` with the relevant parameters after
   finishing positive and negative runs in your main :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_strategy` if
   automatic recording of these information after :meth:`~CovertMark.strategy.strategy.DetectionStrategy.positive_run` and
   :meth:`~CovertMark.strategy.strategy.DetectionStrategy.negative_run` will not suffice (see below).
-  The ability to print debug custom messages if ``DEBUG`` is set to
   ``True``, through the :meth:`~CovertMark.strategy.strategy.DetectionStrategy.debug_print` class method.

**What you need to implement**

In addition to the followed descriptions, implemented methods have more
definitive documentation in their docstrings on what are needed expected
in parameters and returns, and so on.

-  Your strategy should have its own values for class variables ``NAME``
   (the name of your strategy), ``DESCRIPTION`` (a slightly longer
   description of what your strategy does), ``_DEBUG_PREFIX`` to prefix
   your strategy’s debug messages, and ``RUN_CONFIG_DESCRIPTION`` which
   contains a list of strings describing each element of your strategy’s
   run configuration (see below).
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.set_strategic_filter`: Depending on what your strategy examines in
   packets, this method in your strategy should assign to
   ``_strategic_packet_filter`` a dictionary of `MongoDB
   query <https://docs.mongodb.com/manual/tutorial/query-documents/>`__
   as adapted for
   `pymongo <http://api.mongodb.com/python/current/tutorial.html#querying-for-more-than-one-document>`__
   (mostly wrapping comparison operators in strings). For example, if
   your strategy only detects TCP packets, the
   ``{"tcp_info": {"$ne": None}}`` strategic filter will avoid any
   non-TCP packet from being included in ``_pt_traces`` and
   ``_neg_traces``, simplifying the calculation of TPR and FPR. For a
   full list of packet information stored in MongoDB, see the end of
   this documentation segment for a referencing table.
-  Your strategy should contain an internal list of parameters that will
   vary between runs (``config``), which will be represented in a tuple
   of integer, float, or string values. This tuple must be
   consistently-formatted when passed into :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_on_positive`,
   :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_on_negative` and various other methods. The tuple must be the
   same length as the ``RUN_CONFIG_DESCRIPTION`` list, which contains
   descriptions for each element of this configuration tuple. You can
   also add other class constants as necessary.
-  You can specify through :meth:`~CovertMark.strategy.strategy.DetectionStrategy.split_pt` how, if at all, positive
   (``_pt_traces``) and negative traces (``_neg_traces``) can be split
   into training/testing (``_pt_test_traces``) and validation
   (``_pt_validation_traces``) for overfitting checks, which are
   particularly useful for machine learning-based strategies.
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.positive_run`: This method defines how your strategy operates a
   single run on positive packets in ``_pt_traces``. If you have opted
   to split traces in ``split_pt``, you will work on ``_pt_test_traces``
   and ``_pt_validation_traces`` instead. You can retrieve from
   ``_pt_collection_total`` the number of packets matching the
   user-supplied input filters but may or may not have been loaded
   (depending on your strategic filter) if required in TPR calculation.
   You should return the true positive rate of this run on the positive
   packets. Do not call this method directly, but call the wrapper
   method :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_on_positive` instead to allow automatic performance
   recording.
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.negative_run`: This method defines how your strategy operates on
   negative packets between clients and non-proxy servers
   (``_neg_traces``), supplied from a collection or PCAP of “background
   traffic”. Configurations (or related trained classifiers) from
   positive runs should be applied as-is on negative traces to determine
   their likelihood of falsely classifying innocent packets as proxy
   traffic. Again ``_neg_collection_total`` provides the number of
   packets subject to input filters only. You also have access to
   ``_negative_unique_ips``, which gives the number of unique IP
   addresses appearing in the background traffic. You should assign to
   ``_negative_blocked_ips`` a set of unique IP addresses your strategy
   has falsely classified as positive under the current configuration.
   Do not call this method directly, but call the wrapper method
   :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_on_negative` instead to allow automatic performance recording.
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_strategy`: This is the entry point and main routine of your
   strategy. Unless your strategy only needs to run through the positive
   and negative datasets once, you will want to override the default
   code to perform additional setup work or schedule multiple runs. Each
   of these runs on positive and negative traces need to bear a
   consistently-formatted configuration (``config``) as described
   earlier. The ``_strategic_states`` dictionary can be used to store
   additional data that need to be persistently kept between positive
   and negative runs, free for manipulation by different methods within
   your strategy. You can initialise and use other strategy-specific
   class-wide states if desired.
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_strategy` can also receive additional runtime parameters
   through ``**kwargs``, the contents of which can be requested from the
   user by specifying them in the strategy map (see below).
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.report_blocked_ips`: If you want users to be able to view falsely
   blocked packets in Wireshark, this method should return a generated
   string of valid Wireshark display filter. Depending on the nature of
   IP addresses stored in ``_negative_blocked_ips``, you may wish to add
   additional conditions into the generated display filter, such as
   ``ssl && ...`` to only show TLS and SSL packets, or ``tcp.len > 64``
   to show TCP packets with longer than 64 bytes of payload only.
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.interpret_config`: Another ``config``-related method, returning a
   human-readable description of elements of the run configuration to be
   included in the CovertMark summative report. Implement this method if
   you want a more readable description than the default key-value
   pairs.
-  :meth:`~CovertMark.strategy.strategy.DetectionStrategy.config_specific_penalisation`: Also a ``config``-related method.
   Implement this method if you need to additionally penalise a
   configuration by returning a penalty fraction for its large-scale
   deployment complexity by a state censor (which are **unrelated** to
   increases in runtime, which will have been automatically considered
   through execution timing in :meth:`~CovertMark.strategy.strategy.DetectionStrategy.run_on_positive`). An example for an
   appropriate penalisation would be penalties for increased cluster
   size in rare TCP payload length clustering, which will be harder to
   deploy at large-scale as the firewall hardware will need to inspect
   more packets fitting the expanded payload length cluster.

**Within your detection strategy module, things should operate in the
following way:** after initialisation (``__init__``), input-specific
configuration (``setup``) and loading of required traces (``load``),
your ``run_strategy`` should perform any additional setup work needed
and process any additional runtime parameters in ``kwargs``. It should
then schedule a number of :meth:`~CovertMark.strategy.strategy.DetectionStrategy.positive_run` and :meth:`~CovertMark.strategy.strategy.DetectionStrategy.negative_run` based on
determined list of configurations. If manual recording of performance is
required, it should also call :meth:`~CovertMark.strategy.strategy.DetectionStrategy.register_performance_stats` after each
positive or negative run.

In addition to per-configuration performance records available for
exporting and plotting by CovertMark, the strategy itself can run its
own performance comparisons and report through :meth:`~CovertMark.strategy.strategy.DetectionStrategy.debug_print` if
desired. This may be useful for evaluating your strategy independently.

If your strategy can be used in both directions of flow, you do not need
to implement this variability yourself. You can simply specify an
additional strategy run with reversing filters in the strategy map, as
followed.

The Strategy Map
----------------

After implementing your strategy, you need to tell CovertMark how to use
your strategy to test the user’s inputs. This involves adding an entry
to the strategy map (``/CovertMark/strategy/strategy_map.json``).

For your new strategy, you need to add an additional dictionary entry to
the strategy map, with the index being the name of your strategy module
(e.g. ``"entropy_dist"`` for ``/CovertMark/strategy/entropy_dist.py``).
You need the following entries in the dictionary:

+---------------------+-------------------------+---------------------+
| Key                 | Value Type              | Description         |
+=====================+=========================+=====================+
| module              | str                     | The module name of  |
|                     |                         | your strategy       |
|                     |                         | module, same as the |
|                     |                         | strategy key.       |
+---------------------+-------------------------+---------------------+
| object              | str                     | The class name of   |
|                     |                         | the strategy class  |
|                     |                         | in your module.     |
+---------------------+-------------------------+---------------------+
| fixed_params        | list of lists           | Each sub-list       |
|                     |                         | contains an         |
|                     |                         | identifier-qualifyi |
|                     |                         | ng                  |
|                     |                         | string of the name  |
|                     |                         | of a strategy-fixed |
|                     |                         | parameter, as well  |
|                     |                         | as its              |
|                     |                         | corresponding       |
|                     |                         | value. This is      |
|                     |                         | rarely used.        |
+---------------------+-------------------------+---------------------+
| pt_filters          | list                    | What types of input |
|                     |                         | filters are used by |
|                     |                         | your strategy for   |
|                     |                         | positive traces,    |
|                     |                         | expressed in        |
|                     |                         | strings of          |
|                     |                         | ``"IP_SRC"``,       |
|                     |                         | ``"IP_DST"``, and   |
|                     |                         | ``"IP_EITHER"`` and |
|                     |                         | ordered. For        |
|                     |                         | example, to observe |
|                     |                         | client-to-server    |
|                     |                         | packets, use        |
|                     |                         | ``["IP_SRC", "IP_DS\|
|                     |                         | T"]``.              |
|                     |                         | Each represents an  |
|                     |                         | arbitrary number of |
|                     |                         | IP addresses or     |
|                     |                         | subnets the user    |
|                     |                         | can specify of that |
|                     |                         | type. For matching  |
|                     |                         | precedence between  |
|                     |                         | these types, see    |
|                     |                         | :meth:`CovertMark.d\|
|                     |                         | ata.parser.PCAPPars\|
|                     |                         | er.set_ip_filter`.  |
+---------------------+-------------------------+---------------------+
| negative_filters    | list                    | Same as above, but  |
|                     |                         | for negative        |
|                     |                         | traces.             |
+---------------------+-------------------------+---------------------+
| negative_input      | bool                    | If your strategy    |
|                     |                         | does not require    |
|                     |                         | negative traces,    |
|                     |                         | set this to         |
|                     |                         | ``false``. In most  |
|                     |                         | cases negative      |
|                     |                         | traces are needed,  |
|                     |                         | which means that    |
|                     |                         | this will be set to |
|                     |                         | ``true``.           |
+---------------------+-------------------------+---------------------+
| runs                | list of dicts           | See below.          |
+---------------------+-------------------------+---------------------+

Each run of a strategy in its ``runs`` require the following entries:

+---------------------+-------------------------+---------------------+
| Key                 | Value Type              | Description         |
+=====================+=========================+=====================+
| run_order           | int                     | A unique integer    |
|                     |                         | identifying this    |
|                     |                         | run, which normally |
|                     |                         | starts from 0.      |
+---------------------+-------------------------+---------------------+
| run_description     | str                     | If the parent       |
|                     |                         | strategy has        |
|                     |                         | multiple available  |
|                     |                         | runs, a brief       |
|                     |                         | description on what |
|                     |                         | this run is         |
|                     |                         | different with      |
|                     |                         | respect to user     |
|                     |                         | parameters or input |
|                     |                         | filters used.       |
+---------------------+-------------------------+---------------------+
| pt_filters_reverse  | bool                    | If set to true,     |
|                     |                         | this run will       |
|                     |                         | reverse the types   |
|                     |                         | of filters matched  |
|                     |                         | to the user’s       |
|                     |                         | client/server       |
|                     |                         | identification      |
|                     |                         | inputs on the       |
|                     |                         | positive PCAP,      |
|                     |                         | effectively         |
|                     |                         | switching from      |
|                     |                         | e.g. observing      |
|                     |                         | client-to-server    |
|                     |                         | packets to          |
|                     |                         | server-to-client    |
|                     |                         | packets.            |
+---------------------+-------------------------+---------------------+
| negative_filters_re\| bool                    | Same as above, but  |
| verse               |                         | for reversing the   |
|                     |                         | user’s              |
|                     |                         | client/server       |
|                     |                         | identification      |
|                     |                         | inputs on the       |
|                     |                         | negative PCAP.      |
+---------------------+-------------------------+---------------------+
| user_params         | list of lists           | similar to          |
|                     |                         | ``fixed_params`` in |
|                     |                         | the strategy-level  |
|                     |                         | configuration, but  |
|                     |                         | whose parameters    |
|                     |                         | are collected from  |
|                     |                         | the user when       |
|                     |                         | setting up the      |
|                     |                         | individual run of   |
|                     |                         | the strategy,       |
|                     |                         | allowing variations |
|                     |                         | of parameters       |
|                     |                         | requested between   |
|                     |                         | different runs of   |
|                     |                         | the same strategy.  |
+---------------------+-------------------------+---------------------+

After the amendment of the strategy map, your strategy should be ready
to use within CovertMark. However, you may wish to implement means for
direct strategy class execution (through
``if "__name__" == "__main__":``, present in all existing strategy
modules) to test it independently first, to make sure that the detection
techniques work properly, and any configuration-specific penalisation
are properly scaled.

Caveats
-------

It was discovered during the development of the SGD classifier strategy
that sometimes it may be necessary to perform the strategy run in a way
unanticipated by the designed separation of :meth:`~CovertMark.strategy.strategy.DetectionStrategy.positive_run` and
:meth:`~CovertMark.strategy.strategy.DetectionStrategy.negative_run` in the abstract class. If both positive and negative
runs need to be placed within the same method, automated performance
recording will become erroneous, which require manual registration of
performance by calling :meth:`~CovertMark.strategy.strategy.DetectionStrategy.register_performance_stats` at the appropriate
points. Some other protected and private variables storing strategy
states may also need to be manually updated or reset.

For machine learning-based strategies with nondeterminism, it is
recommended that in addition to validating the classifier on unseen
packets from the same positive and negative PCAPs as the training
packets, you also use ``test_recall`` and relevant parameters in
``__init__`` and ``setup``, as well as ``recall_run`` to perform the
same validation on a separately-recorded PCAP of the same protocol’s
traffic as well (see :mod:`CovertMark.strategy.sgd`). This is due to the
fact that unsuitable selections of traffic features can cause severe
overfitting and low unseen recall performance on classifying the same
proxy protocol carrying different types of traffic or under different
network conditions.

Due to the need for accurate inter-packet timing in traffic shaping,
input PCAPs should have at least 6 decimal places (microsecond) of
accuracy in packet arrival times. This is standard for those captured
with Wireshark or Linux/OS X tcpdump.

MongoDB Packet Record Format
----------------------------

The following are the keys and their descriptions in each dictionary
representing a packet parsed, which are the elements of ``_pt_traces``
and ``_neg_traces`` lists.

+-----------------------------------+-----------------------------------+
| Key                               | Description                       |
+===================================+===================================+
| type                              | Type of IP packet: ``v4`` or      |
|                                   | ``v6``.                           |
+-----------------------------------+-----------------------------------+
| dst                               | Destination IP address, can be    |
|                                   | IPv4 or IPv6.                     |
+-----------------------------------+-----------------------------------+
| src                               | Source IP address, can be IPv4 or |
|                                   | IPv6.                             |
+-----------------------------------+-----------------------------------+
| len                               | IP layer length of the packet.    |
+-----------------------------------+-----------------------------------+
| proto                             | Protocol of transport layer,      |
|                                   | usually ``TCP`` or ``UDP``.       |
+-----------------------------------+-----------------------------------+
| time                              | The UNIX timestamp marking the    |
|                                   | packet’s capture, with at least 6 |
|                                   | decimal places of accuracy.       |
+-----------------------------------+-----------------------------------+
| ttl                               | The time-to-live of IPv4 packets  |
|                                   | in ms, of the remaining hop limit |
|                                   | of IPv6 packets.                  |
+-----------------------------------+-----------------------------------+
| tcp_info                          | A dictionary containing           |
|                                   | additional information for TCP    |
|                                   | packets on the transport layer,   |
|                                   | detailed blow. Value is None if   |
|                                   | the packet is not a TCP packet.   |
+-----------------------------------+-----------------------------------+
| tcp_info.sport                    | Integer value of source port.     |
+-----------------------------------+-----------------------------------+
| tcp_info.dport                    | Integer value of destination      |
|                                   | port.                             |
+-----------------------------------+-----------------------------------+
| tcp_info.flags                    | A dictionary of TCP values and    |
|                                   | their set/unset (0/1) values,     |
|                                   | including ``FIN``, ``PSH``,       |
|                                   | ``SYN``, ``ACK``, ``URG``,        |
|                                   | ``ECE``, and ``CWR`` as keys.     |
+-----------------------------------+-----------------------------------+
| tcp_info.opts                     | A list of (option number, option  |
|                                   | value) tuples storing the         |
|                                   | packet’s TCP options.             |
+-----------------------------------+-----------------------------------+
| tcp_info.seq                      | The absolute SEQ number of the    |
|                                   | TCP packet.                       |
+-----------------------------------+-----------------------------------+
| tcp_info.ack                      | The absolute ACK number of the    |
|                                   | TCP packet.                       |
+-----------------------------------+-----------------------------------+
| tcp_info.payload                  | The TCP payload carried, which    |
|                                   | will be Base64-encoded when       |
|                                   | stored, but always in raw bytes   |
|                                   | when available to the detection   |
|                                   | strategy.                         |
+-----------------------------------+-----------------------------------+
| tls_info                          | A dictionary containing           |
|                                   | additional information for TLS    |
|                                   | packets on the application layer, |
|                                   | detailed blow. Value is None if   |
|                                   | the TCP packet is not a TLS       |
|                                   | packet.                           |
+-----------------------------------+-----------------------------------+
| tls_info.type                     | The type of TLS message           |
|                                   | transmitted, one of               |
|                                   | ``CHANGE_CIPHER_SPEC``,           |
|                                   | ``ALERT``, ``HANDSHAKE``, or      |
|                                   | ``APPLICATION_DATA``.             |
+-----------------------------------+-----------------------------------+
| tls_info.ver                      | The version of TLS protocol used, |
|                                   | one of ``1.0``, ``1.1``, ``1.2``, |
|                                   | ``1.3``.                          |
+-----------------------------------+-----------------------------------+
| tls_info.len                      | The total length of all TLS       |
|                                   | records carried. Each complete    |
|                                   | TLS packet may carry several TLS  |
|                                   | records, but usually at most 2.   |
+-----------------------------------+-----------------------------------+
| tls_info.records                  | The total number of TLS records   |
|                                   | carried by the complete TLS       |
|                                   | packet.                           |
+-----------------------------------+-----------------------------------+
| tls_info.data                     | A list of TLS data/payloads in    |
|                                   | each TLS record, each             |
|                                   | Base64-encoded when stored but    |
|                                   | always in raw bytes when          |
|                                   | available to a detection          |
|                                   | strategy.                         |
+-----------------------------------+-----------------------------------+
| tls_info.data_length              | A list of payload lengths         |
|                                   | matching the payloads in          |
|                                   | ``tls_info.data``.                |
+-----------------------------------+-----------------------------------+

References
----------

[1] https://kpdyer.com/publications/ccs2015-measurement.pdf
