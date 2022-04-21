import numpy as np

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

import sys


def classify(train_features, train_labels, test_features, test_labels):

    """Function to perform classification, using a
    Random Forest.

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html

    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. We prefer to use all the jobs our processor can handle, we are people in a hurry
    clf = RandomForestClassifier(n_jobs=-1, n_estimators=255)
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)

    return predictions


def perform_crossval(features, labels, folds=10):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.

    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold.

    You need to use the data returned by classify() over all folds
    to evaluate the performance.
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)

    index = 0
    total_accuracy = 0.0
    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test, y_test)
        nb_correct = sum(
            map(lambda x: 1 if x[0] == x[1] else 0, zip(predictions, y_test))
        )
        # print(
        #     "correct prediction rate at round {}: {}".format(
        #         index, float(nb_correct) / len(predictions)
        #     )
        # )
        index += 1
        total_accuracy += float(nb_correct) / len(predictions)
    print("total average correct rate: {}".format(total_accuracy / index))

    ###############################################
    # TODO: Write code to evaluate the performance of your classifier
    ###############################################


def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace

    Assume we have traces (trace1...traceN) for cells with IDs in the
    range 1-N.

    We extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Our inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Please, refer to trace_data_extraction/trace_data_extraction.ipynb for details on chosen features
    """

    features_data = pd.read_csv("trace_data_extraction/features.csv").to_numpy(dtype=int)

    features = features_data.transpose()[1:].transpose()
    labels = features_data.transpose()[0]

    return features, labels


def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification
    using a Random Forest classifier. You are free to modify the
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    perform_crossval(features, labels, folds=10)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
