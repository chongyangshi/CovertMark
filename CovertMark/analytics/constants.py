"""
This module stores fixed configurations used in traffic analysis for ease of maintenance.
"""
INITIAL_RANDOM_BLOCK_COUNT = 2048
A_D_THRESHOLDS = [0.25, 0.1, 0.05, 0.025, 0.01]
MOST_FREQUENT_COUNT = 5
USE_ENTROPY = 'entropy'
USE_INTERVAL = 'interval'
USE_INTERVAL_BINS = 'interval_bins'
USE_TCP_LEN = 'tcp_len'
USE_TCP_LEN_BINS = 'tcp_len_bins'
USE_PSH = 'psh'
FEATURES = [USE_ENTROPY, USE_INTERVAL, USE_TCP_LEN, USE_INTERVAL_BINS, USE_TCP_LEN_BINS, USE_PSH]
MTU_FRAME_AVOIDANCE_THRESHOLD = 1450 # For TCP payload lengths.
