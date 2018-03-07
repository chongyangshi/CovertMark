import matplotlib.pyplot as plt
import csv
import numpy as np
from collections import defaultdict
from operator import itemgetter

COLOURS = ['b', 'g', 'r', 'y']

def plot_fprs(csvs_in, names, show=True, img_out=None, title=None):
    """
    Given CSVs containing the occurrence thresholds, and FPR rates. Produce a
    curve with errorbars containing these information.
    :param csvs_in: input CSVs, each must contain all information above in unique
        columns.
    :param names: list of strings giving legend of the lines plotted, must match
        the length of csvs_in.
    :param show: if True, show the plot through a GUI interface.
    :param img_out: if set, output the plot to the path specified in this.
    :param title: if set, display the title as specified in string.
    :returns: True if plot successfully, False otherwise.
    """

    if len(names) != len(csvs_in):
        return False

    fig, fpr_axis = plt.subplots(1, 1)
    if title is not None:
        fpr_axis.set_title(title)

    for n, csv_in in enumerate(csvs_in):
        line_colour = COLOURS[n % len(COLOURS)] # Alternating colours.
        FPRs = defaultdict(list)

        with open(csv_in, 'r') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")

            threshold_key = [k for k in reader.fieldnames if 'threshold' in k.lower()]
            FPR_key = [k for k in reader.fieldnames if 'fpr' in k.lower()]

            if len(FPR_key) != 1 or len(threshold_key) != 1:
                return False

            threshold_key = threshold_key[0]
            FPR_key = FPR_key[0]

            for row in reader:
                FPRs[int(row[threshold_key])].append(float(row[FPR_key]))

        if len(FPRs) < 1:
            return False

        thresholds = sorted(FPRs.keys())
        FPR_values = [np.mean(i[1]) for i in sorted(FPRs.items(), key=itemgetter(0))]
        FPR_errors_max = [np.max(i[1])-np.mean(i[1]) for i in sorted(FPRs.items(), key=itemgetter(0))]
        FPR_errors_min = [np.mean(i[1])-np.min(i[1]) for i in sorted(FPRs.items(), key=itemgetter(0))]
        fpr_axis.plot(thresholds, FPR_values, '-', label=names[n], color=line_colour)
        fpr_axis.set_xlabel(threshold_key)
        fpr_axis.set_ylabel(FPR_key, color='k')
        fpr_axis.grid(color='k', which='both', axis='both', alpha=0.25, linestyle='dashed')
        fpr_axis.errorbar(thresholds, FPR_values, yerr=[FPR_errors_min, FPR_errors_max],
         marker='+', capsize=5, color=line_colour, ecolor=line_colour)

    fpr_axis.set_ylim(ymin=0)
    fpr_axis.legend()

    if img_out is not None:
        plt.savefig(img_out, dpi=200)

    if show:
        plt.show()

    return True


def plot_ips(csvs_in, names, show=True, img_out=None, title=None):
    """
    Given CSVs containing the occurrence thresholds, and IP block rates. Produce
    a curve with errorbars containing these information.
    :param csvs_in: input CSVs, each must contain all information above in unique
        columns.
    :param names: list of strings giving legend of the lines plotted, must match
        the length of csvs_in.
    :param show: if True, show the plot through a GUI interface.
    :param img_out: if set, output the plot to the path specified in this.
    :param title: if set, display the title as specified in string.
    :returns: True if plot successfully, False otherwise.
    """

    if len(names) != len(csvs_in):
        return False

    fig, ip_axis = plt.subplots(1, 1)
    if title is not None:
        ip_axis.set_title(title)

    for n, csv_in in enumerate(csvs_in):
        line_colour = COLOURS[n % len(COLOURS)] # Alternating colours.
        IPs = defaultdict(list)

        with open(csv_in, 'r') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")

            threshold_key = [k for k in reader.fieldnames if 'threshold' in k.lower()]
            IP_key = [k for k in reader.fieldnames if 'ip' in k.lower()]

            if len(IP_key) != 1 or len(threshold_key) != 1:
                return False

            threshold_key = threshold_key[0]
            IP_key = IP_key[0]

            for row in reader:
                IPs[int(row[threshold_key])].append(float(row[IP_key]))

        if len(IPs) < 1:
            return False

        thresholds = sorted(IPs.keys())
        IP_values = [np.mean(i[1]) for i in sorted(IPs.items(), key=itemgetter(0))]
        IP_errors_max = [np.max(i[1])-np.mean(i[1]) for i in sorted(IPs.items(), key=itemgetter(0))]
        IP_errors_min = [np.mean(i[1])-np.min(i[1]) for i in sorted(IPs.items(), key=itemgetter(0))]

        ip_axis.plot(thresholds, IP_values, '-', color=line_colour, label=names[n])
        ip_axis.set_xlabel(threshold_key)
        ip_axis.set_ylabel(IP_key, color='k')
        ip_axis.grid(color='k', which='both', axis='both', alpha=0.25, linestyle='dashed')
        ip_axis.errorbar(thresholds, IP_values, yerr=[IP_errors_min, IP_errors_max],
         marker='+', capsize=5, color=line_colour, ecolor=line_colour)

    ip_axis.set_ylim(ymin=0)
    ip_axis.legend()
    if img_out is not None:
        plt.savefig(img_out, dpi=200)

    if show:
        plt.show()

    return True


def plot_fnrs(csvs_in, names, show=True, img_out=None, title=None):
    """
    Given CSVs containing the occurrence thresholds, and false negative rates.
    Produce scatterplot containing these information.
    :param csvs_in: input CSVs, each must contain all information above in unique
        columns.
    :param names: list of strings giving legend of the lines plotted, must match
        the length of csvs_in.
    :param show: if True, show the plot through a GUI interface.
    :param img_out: if set, output the plot to the path specified in this.
    :param title: if set, display the title as specified in string.
    :returns: True if plot successfully, False otherwise.
    """

    if len(names) != len(csvs_in):
        return False

    fig, fnr_axis = plt.subplots(1, 1)
    if title is not None:
        fnr_axis.set_title(title)

    for n, csv_in in enumerate(csvs_in):
        line_colour = COLOURS[n % len(COLOURS)] # Alternating colours.
        FNRs = []
        thresholds = []

        with open(csv_in, 'r') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")

            threshold_key = [k for k in reader.fieldnames if 'threshold' in k.lower()]
            FNR_key = [k for k in reader.fieldnames if 'fnr' in k.lower()]

            if len(FNR_key) != 1 or len(threshold_key) != 1:
                return False

            threshold_key = threshold_key[0]
            FNR_key = FNR_key[0]

            for row in reader:
                FNRs.append(float(row[FNR_key]))
                thresholds.append(float(row[threshold_key]))

        if len(FNRs) < 1:
            return False

        fnr_axis.scatter(thresholds, FNRs, marker='.', c=line_colour, label=names[n])
        fnr_axis.set_xlabel(threshold_key)
        fnr_axis.set_ylabel(FNR_key, color='k')
        fnr_axis.grid(color='k', which='both', axis='both', alpha=0.25, linestyle='dashed')

    fnr_axis.set_ylim(ymin=0)
    fnr_axis.legend()
    if img_out is not None:
        plt.savefig(img_out, dpi=200)

    if show:
        plt.show()

    return True
