import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import csv

def plot_fpr_fnr(csv_in, show=True, img_out=None):
    """
    Given a CSV containing the occurrence thresholds, FPR and FNR rates, plot a
    scatterplot containing both information.
    :param csv_in: input CSV, must contain all information above in unique columns.
    :param show: if True, show the plot through a GUI interface.
    :param img_out: if set, output the plot to the path specified in this.
    :returns: True if plot successfully, False otherwise.
    """

    thresholds = []
    FPRs = []
    FNRs = []

    with open(csv_in, 'r') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=",")

        if len(reader) < 1:
            return False

        threshold_key = [k for k in reader[0].keys() if 'threshold' in k.lower()]
        FPR_key = [k for k in reader[0].keys() if 'fpr' in k.lower()]
        FNR_key = [k for k in reader[0].keys() if 'fnr' in k.lower()]

        if len(FPR_key) != 1 or len(FNR_key) != 1 or len(threshold_key) != 1:
            return False

        threshold_key = threshold_key[0]
        FPR_key = FPR_key[0]
        FNR_key = FNR_key[0]

        for row in reader:
            thresholds.append(int(row[threshold_key]))
            FPRs.append(float(row[FPR_key]))
            FNRs.append(float(row[FNR_key]))

    if len(thresholds) < 1:
        return False

    fig, fpr_axis = plt.subplots()
    fpr_axis.plot(thresholds, FPRs, 'b.')
    fpr_axis.set_xlabel(threshold_key)
    fpr_axis.set_ylabel(FPR_key, color='b')
    fpr_axis.grid(color='k', which='both', aixs='both')
    fpr_axis.tick_params('y', colors='b')

    fnr_axis = fpr_axis.twinx()
    fnr_axis.plot(thresholds, FNRs, 'r.')
    fnr_axis.set_ylabel(FNR_key, color='r')
    fnr_axis.tick_params('y', colors='r')

    fig.tight_layout()

    if show:
        plt.show()

    if img_out is not None:
        savefig(img_out, bbox_inches='tight')

    return True
