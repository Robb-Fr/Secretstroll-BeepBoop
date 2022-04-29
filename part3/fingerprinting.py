import numpy as np
from numpy.typing import NDArray
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

import sys


def sort_predictions_proba(
    predictions_proba: NDArray, y_test: NDArray
) -> list[tuple[int, list[tuple[int, float]]]]:
    """Computes the list of sorted by probability (predicted label, probability of prediction) associated to each test label for a given classification.
    
    Returns:
        - a list of (true_label,ordered_by_probability_predicted_label) where ordered_by_probability_predicted_label is a list of tuples associating a predicted label to its prediction probability"""
    ordered_classifier_proba_results = []
    for y, pred_prob in zip(y_test, predictions_proba):
        enumerated_pred_prob = list(
            map(lambda x: (x[0] + 1, x[1]), enumerate(pred_prob))
        )
        sorted_pred_prob = list(
            filter(
                lambda x: x[1] > 0.0,
                sorted(enumerated_pred_prob, key=lambda x: x[1], reverse=True),
            )
        )
        ordered_classifier_proba_results += [(y, sorted_pred_prob)]
    return ordered_classifier_proba_results


def accuracy_of_N_top_predictions(
    predictions_proba: NDArray, y_test: NDArray, N: int = 100
) -> float:
    """Gives the accuracy of the predictions in a relaxed version where the top N predictions are considered instead of only the first one"""
    sorted_pred_proba = sort_predictions_proba(predictions_proba, y_test)
    nb_IN_N_tops = 0
    for y, sorted_pred in sorted_pred_proba:
        sorted_pred_labels = list(map(lambda x: x[0], sorted_pred))
        nb_IN_N_tops += 1 if y in sorted_pred_labels[:N] else 0
    return float(nb_IN_N_tops) / len(predictions_proba)


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
    clf = RandomForestClassifier(n_jobs=-1, n_estimators=260)
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    # Use the classifier to give the list of predictions probabilities on each test feature
    predictions_proba = clf.predict_proba(test_features)

    return predictions, predictions_proba, clf.score(test_features, test_labels)


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

    total_accuracy = 0.0
    total_top_2_accuracy = 0.0
    total_top_10_accuracy = 0.0
    total_rate_of_presence_of_label_in_predictions = 0.0
    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions, predictions_proba, score = classify(
            X_train, y_train, X_test, y_test
        )
        total_top_2_accuracy += accuracy_of_N_top_predictions(
            predictions_proba, y_test, 2
        )
        total_top_10_accuracy += accuracy_of_N_top_predictions(
            predictions_proba, y_test, 10
        )
        total_rate_of_presence_of_label_in_predictions += accuracy_of_N_top_predictions(
            predictions_proba, y_test
        )
        total_accuracy += score
    print("average correct prediction rate: {}".format(total_accuracy / folds))
    print("average correct prediction rate in top 2: {}".format(total_top_2_accuracy / folds))
    print("average correct prediction rate in top 10: {}".format(total_top_10_accuracy / folds))
    print(
        "average proportion of classification that include correct answer with a non-null probability: {}".format(
            total_rate_of_presence_of_label_in_predictions / folds
        )
    )

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

    features_data = (
        pd.read_csv("trace_data_extraction/features.csv")
        .filter(regex="label|round\d+_size|size|nb_rounds")
        .to_numpy(dtype=int)
    )

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
