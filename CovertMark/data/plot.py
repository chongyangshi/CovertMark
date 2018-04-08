from . import utils

import os
import matplotlib as mpl
mpl.use('Agg') # Fixes non-TK dependency issues on some platforms.
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import csv
import numpy as np
from collections import defaultdict
from operator import itemgetter
from math import floor

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
    :param str img_out: if set, output the plot to the path specified.
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


def plot_hist(lengths, x_name, y_name, show=True, img_out=None,
 title=None, bin_width=10):
    """
    Given a list of TCP payload lengths (or some other kind of 1D data),
    plot a historam showing the distribution of these payload lengths.
    
    :param list lengths: a list of integer payload lengths.
    :param str x_name: the name of the x-axis property.
    :param str y_name: the name of the y-axis property.
    :param bool show: if True, show the plot through a GUI interface.
    :param str img_out: if set, output the plot to the path specified.
    :param str title: if set, display the title as specified in string.
    :param int bin_width: if set decides the width of bins, 10 by default.
    :returns: True if plot successfully, False otherwise.
    """

    if any([not isinstance(x, int) or x < 0 for x in lengths]):
        return False
    
    if not isinstance(x_name, str) or not isinstance(y_name, str):
        return False

    if title and not isinstance(title, str):
        return False

    bins = floor(max(lengths) / bin_width)
    weights = np.ones_like(lengths) / (len(lengths))
    
    n, bins, patches = plt.hist(lengths, bins=bins, range=(0, max(lengths)),
     weights=weights, facecolor='g', alpha=0.75)
    plt.xlabel(x_name)
    plt.ylabel(y_name)

    if title:
        plt.title(title)
    
    plt.grid(color='k', which='both', axis='both', alpha=0.25, linestyle='dashed')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(to_percent))
    
    if img_out is not None:
        out_path = utils.get_full_path(img_out)
        if out_path:
            plt.savefig(os.path.expanduser(out_path), dpi=200)

    if show:
        plt.show()

    return True


def to_percent(y, position):
    """
    Percentage label formatter from matplotlib.
    Taken from https://matplotlib.org/examples/pylab_examples/histogram_percent_demo.html.
    """
            
    # Ignore the passed in position. This has the effect of scaling the default
    # tick locations.
    s = str(round(100 * y, 1))

    # The percent symbol needs escaping in latex
    if mpl.rcParams['text.usetex'] is True:
        return s + r'$\%$'
    else:
        return s + '%'