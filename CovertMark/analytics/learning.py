from . import constants, entropy
from ..data import utils as data_utils

from abc import ABC
from sklearn import preprocessing, model_selection, linear_model

"""
Different classifier architectures that can be used for traffic classification.
"""

class Classifier(ABC):
    """
    Abstract class for common classifier methods.
    """

    def __init__(self, classifier):
        self.__classifier = classifier


    def train(self, training_features, training_labels):
        """
        :param list training_features: input rows of features for training, without
         labels. These should be redrawn between training runs.
        :param list training_labels: corresponding labels for the input rows.
        """

        assert(len(training_features) > 0)
        assert(len(training_features) == len(training_labels))

        self._feature_width = len(training_features[0])
        self.__classifier.fit(training_features, training_labels)


    def predict(self, validation_inputs):
        """
        Classify unseen inputs, can be used for both validation prediction and
         recall prediction.
        :param list validation_inputs: input rows of features for validation,
         should not have been seen during training.
        :returns: array of positive(1) / negative(0) labels predicted.
        """

        assert(len(validation_inputs) > 0)
        assert(self._feature_width == len(validation_inputs[0]))

        return self.__classifier.predict(validation_inputs)



class LogisticRegression(Classifier):
    """
    Generic logistic regression with stable L1 penalisation and fast SAGA solver
    to converge quickly, but can overfit on high dimensional spaces.
    """

    def __init__(self, multithreaded=True):
        n_jobs = -1 if multithreaded else 1
        self.__classifier = linear_model.LogisticRegression(penalty='l1',
         dual=False, solver='saga', n_jobs=n_jobs, max_iter=5000, warm_start=False)
        super().__init__(self.__classifier)


class SDG(Classifier):
    """
    Stochastic gradient descent linear classification, as a less memory-intensive
    and incremental learning-compatible alternative to linear SVM (LinearSVC).
    """

    def __init__(self, loss="hinge", multithreaded=True):
        assert(loss in ["hinge", "modified_huber", "squared_hinge"])
        n_jobs = -1 if multithreaded else 1
        self.__classifier = linear_model.SGDClassifier(penalty='l1',
         loss=loss, max_iter=5000, n_jobs=n_jobs, learning_rate='optimal',
         warm_start=False)
        super().__init__(self.__classifier)
