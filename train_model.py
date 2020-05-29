import pathlib
import csv
import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from scipy import stats
from sklearn.model_selection import train_test_split
from sklearn.model_selection import RandomizedSearchCV
from sklearn.model_selection import train_test_split
from dataset import get_dataset

features_names = [
    "incoming_packets_count",
    "outgoing_packets_count",
    "total_packet_count",
    "incoming_packets_fraction",
    "outgoing_packets_fraction",
    "total_time",
    "outgoing_packets_concentration_mean",
    "outgoing_packets_concentration_std",
    "outgoing_packets_concentration_min",
    "outgoing_packets_concentration_max",
    "average_time_between_incoming_packets",
    "average_time_between_outgoing_packets",
    "nbr_bytes_data_sent",
    "nbr_bytes_data_received",
    "avg_bytes_data_sent",
    "avg_bytes_data_received",
    "nbr_reassembled_packets",
    "nbr_TCP_packets",
    "nbr_TLS_packets",
    "time_of_first_response"
]

def print_feature_importances_(feature_importances_):
    print("[...] Feature importances")
    for i, imp in enumerate(feature_importances_):
        print("{},{:2.2f}".format(features_names[i], imp*100))


kfold_count = 10

X, y = get_dataset()

print("[...] Data ready")

print("[...] Data split into training and testing set")
data_train, data_test, target_train, target_test = train_test_split(
    X, y, test_size=0.3)

# Split and train/validate for each fold
kf = StratifiedKFold(n_splits=kfold_count)
tot_acc = 0
clf = RandomForestClassifier(random_state=0, n_jobs=-1, max_features="sqrt", n_estimators=400) # n_estimators is coming from grid_search.py
print("[...] Cross validation")
accuracies = []
for idx, (train_index, test_index) in enumerate(kf.split(data_train, target_train), 1):
    X_train, y_train = data_train[train_index], target_train[train_index]
    X_validation, y_validation = data_train[test_index], target_train[test_index]

    # Train model
    clf.fit(X_train, y_train)

    # Predict on validation data
    acc = clf.score(X_validation, y_validation) * 100
    accuracies.append(acc)

    print("[...] Accuracy of batch {:2d} = {:2.2f}%".format(idx, acc))

print("[...] Mean accuracy = {:2.2f}%".format(np.mean(accuracies)))
print("[...] Std of accuracy = {:2.2f}%".format(np.std(accuracies)))


# Show importance of each feature (in the array returned by record_to_features())
print_feature_importances_(clf.feature_importances_)

print("[...] Accuracy on test data: {:2.2f}%".format(
    clf.score(data_test, target_test)*100))
