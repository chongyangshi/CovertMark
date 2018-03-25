from . import utils

import os
import matplotlib as mpl
mpl.use('Agg') # Fixes non-TK dependency issues on some platforms.
import matplotlib.pyplot as plt
import csv
import numpy as np
from collections import defaultdict
from operator import itemgetter

COLOURS = ['b', 'g', 'r', 'y']

def plot_performance(csvs_in, names, x_name, y_name, show=True, img_out=None,
 title=None):
    """
    Given CSVs containing the same x-axis and y-axis properties, and roduce
    curves with errorbars containing these information.
    :param list csvs_in: input CSVs, each must contain all information above in
        unique columns.
    :param str names: list of strings giving legend of the lines plotted, must
        match the length of `csvs_in`.
    :param str x_name: the name of the shared x-axis property.
    :param str y_name: the name of the shared y-axis property.
    :param bool show: if True, show the plot through a GUI interface.
    :param str img_out: if set, output the plot to the path specified..
    :param str title: if set, display the title as specified in string.
    :returns: True if plot successfully, False otherwise.
    """

    if len(names) != len(csvs_in):
        return False

    fig, axis = plt.subplots(1, 1)
    if title is not None:
        axis.set_title(title)

    for n, csv_in in enumerate(csvs_in):
        line_colour = COLOURS[n % len(COLOURS)] # Alternating colours.
        y_content = defaultdict(list)

        with open(os.path.expanduser(csv_in), 'r') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")

            x_key = [k for k in reader.fieldnames if x_name.lower() in k.lower()]
            y_key = [k for k in reader.fieldnames if y_name.lower() in k.lower()]

            if len(y_key) != 1 or len(x_key) != 1:
                return False

            x_key = x_key[0]
            y_key = y_key[0]

            for row in reader:
                y_content[float(row[x_key])].append(float(row[y_key]))

        if len(y_content) < 1:
            return False

        thresholds = sorted(y_content.keys())
        y_values = [np.mean(i[1]) for i in sorted(y_content.items(), key=itemgetter(0))]
        y_errors_max = [np.max(i[1])-np.mean(i[1]) for i in sorted(y_content.items(), key=itemgetter(0))]
        y_errors_min = [np.mean(i[1])-np.min(i[1]) for i in sorted(y_content.items(), key=itemgetter(0))]
        axis.plot(thresholds, y_values, '-', label=names[n], color=line_colour)
        axis.set_xlabel(x_key)
        axis.set_ylabel(y_key, color='k')
        axis.grid(color='k', which='both', axis='both', alpha=0.25, linestyle='dashed')
        axis.errorbar(thresholds, y_values, yerr=[y_errors_min, y_errors_max],
         marker='+', capsize=5, color=line_colour, ecolor=line_colour)

    axis.set_ylim(ymin=0)
    axis.legend()

    if img_out is not None:
        out_path = utils.get_full_path(img_out)
        if out_path:
            plt.savefig(os.path.expanduser(out_path), dpi=200)

    if show:
        plt.show()

    return True
