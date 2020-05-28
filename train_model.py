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

captures_folders = ["captures_sacha", "captures_ricardo","captures_sacha_2","captures_ricardo_2"]
#captures_folders = ["captures_sacha"]
ipv4_regex = '^172\.19\.0\.3|172\.18\.0\.2$'
#host_addresses = ["172.19.0.3", "172.18.0.2"]
cell_count = 100
seed = 0
kfold_count = 10

#
# Functions to extract features from record
#
def incoming_packets_count(df):
    return len(df[df['Destination'].str.contains(ipv4_regex, regex=True)])

def outgoing_packets_count(df):
    return len(df[df['Source'].str.contains(ipv4_regex, regex=True)])

def total_packet_count(df):
    return len(df)

def incoming_packets_fraction(df):
    return incoming_packets_count(df) / total_packet_count(df)

def outgoing_packets_fraction(df):
    return outgoing_packets_count(df) / total_packet_count(df)

def total_time(df):
    return df['Time'].iat[-1]

def outgoing_packets_concentration_mean(df, window_size=20):
    packets = df['Source'].str.contains(ipv4_regex, regex=True)
    return packets.rolling(window_size).sum()[window_size-1::window_size].dropna().mean()

def outgoing_packets_concentration_std(df, window_size=20):
    packets = df['Source'].str.contains(ipv4_regex, regex=True)
    return packets.rolling(window_size).sum()[window_size-1::window_size].dropna().std()

def outgoing_packets_concentration_min(df, window_size=20):
    packets = df['Source'].str.contains(ipv4_regex, regex=True)
    return packets.rolling(window_size).sum()[window_size-1::window_size].dropna().min()

def outgoing_packets_concentration_max(df, window_size=20):
    packets = df['Source'].str.contains(ipv4_regex, regex=True)
    return packets.rolling(window_size).sum()[window_size-1::window_size].dropna().max()


def average_time_between_incoming_packets(df, window_size=20):
    packets = df[df['Destination'].str.contains(ipv4_regex, regex=True)]
    zipped = list(zip(packets[1:]["Time"], packets[:-1]["Time"]))
    diffs = list(map(lambda x: x[0]-x[1], zipped))
    return pd.DataFrame(diffs).mean()

def average_time_between_outgoing_packets(df, window_size=20):
    packets = df[df['Source'].str.contains(ipv4_regex, regex=True)]
    zipped = list(zip(packets[1:]["Time"], packets[:-1]["Time"]))
    diffs = list(map(lambda x: x[0]-x[1], zipped))
    return pd.DataFrame(diffs).mean()
    

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
    "average_time_between_outgoing_packets" ]

def record_to_features(df):
    return [
        incoming_packets_count(df),
        outgoing_packets_count(df),
        total_packet_count(df),
        incoming_packets_fraction(df),
        outgoing_packets_fraction(df),
        total_time(df),
        outgoing_packets_concentration_mean(df),
        outgoing_packets_concentration_std(df),
        outgoing_packets_concentration_min(df),
        outgoing_packets_concentration_max(df),
        average_time_between_incoming_packets(df),
        average_time_between_outgoing_packets(df)
    ]

def print_feature_importances_(feature_importances_):
    for i, imp in enumerate(feature_importances_):
        print(f"{features_names[i]}: {imp}")

def preprocess_record(df):
    # Remove ARP packets:
    df = df[df['Protocol'] != 'ARP']
    
    return df

def get_records(captures_folders):
    '''Iterate in the captures folders and return a dict mapping the cell ID to an array of Pandas record'''
    records = {}

    for cell in range(1, cell_count + 1):
        records[cell] = []
        for folder in captures_folders:
            cell_folder = pathlib.Path(folder) / "cell_{}".format(cell)
            for run_csv in cell_folder.glob("*.csv"):
                df = pd.read_csv(run_csv) 
                if len(df) == 0:
                    continue
                df = df.rename(lambda x: x.split('.')[-1], axis='columns') # Remove the _ws.col. prefix in the columns name
                records[cell].append(preprocess_record(df))
    return records

def evaluate(model, test_features, test_labels):
    predictions = model.predict(test_features)
    errors = abs(predictions - test_labels)
    mape = 100 * np.mean(errors / test_labels)
    accuracy = 100 - mape
    print('Model Performance')
    print('Average Error: {:0.4f} degrees.'.format(np.mean(errors)))
    print('Accuracy = {:0.2f}%.'.format(accuracy))
    
    return accuracy


# Get records list
print("[...] Getting records")
records = get_records(captures_folders)

# Clean up data
print("[...] Cleaning up data")
for cell in range(1, cell_count + 1):
    cell_records = records[cell]
    
    # Only keep values that are between [mean-1.5std, mean+1.5std]
    # (find Tor crashes, and so on)
    tot_times = pd.DataFrame(list(map(total_time, cell_records)))
    is_in_std = tot_times.apply(stats.zscore).apply(np.abs) < 1.5
    
    # Only keep records with #packets >= 20 * 2 (to use concentration features)
    # (find big outliers)
    tot_packets = pd.DataFrame(list(map(total_packet_count, cell_records)))
    has_enough_packets = tot_packets >= 40

    # Combine conditions
    should_select = is_in_std & has_enough_packets
    
    # Filter records
    records[cell] = [rec for idx, rec in enumerate(cell_records) if should_select.iat[idx, 0]]


# Create dataset
X = []
y = []
for cell_id, cell_records in records.items():
    for idx, cell_record in enumerate(cell_records):
        features = record_to_features(cell_record)
        X.append(features)
        y.append(cell_id)

# Shuffle dataset
random.seed(seed)
random.shuffle(X)
random.seed(seed)
random.shuffle(y)

X = np.array(X)
y = np.array(y)

print("[...] Data ready")

print("[...] Data split into training and testing set")
data_train, data_test, target_train, target_test = train_test_split(X,y, test_size=0.3)

# print("[...] Random search on parameters")
# # Number of trees in random forest
# n_estimators = [int(x) for x in np.linspace(start = 200, stop = 2000, num = 10)]
# # Number of features to consider at every split
# max_features = ['auto', 'sqrt']
# # Maximum number of levels in tree
# max_depth = [int(x) for x in np.linspace(10, 110, num = 11)]
# max_depth.append(None)
# # Minimum number of samples required to split a node
# min_samples_split = [2, 5, 10]
# # Minimum number of samples required at each leaf node
# min_samples_leaf = [1, 2, 4]
# # Method of selecting samples for training each tree
# bootstrap = [True, False]# Create the random grid
# random_grid = {'n_estimators': n_estimators,
#                'max_features': max_features,
#                'max_depth': max_depth,
#                'min_samples_split': min_samples_split,
#                'min_samples_leaf': min_samples_leaf,
#                'bootstrap': bootstrap}
# # Use the random grid to search for best hyperparameters
# # First create the base model to tune
# rf = RandomForestClassifier()
# # Random search of parameters, using 3 fold cross validation, 
# # search across 100 different combinations, and use all available cores
# rf_random = RandomizedSearchCV(estimator = rf, param_distributions = random_grid, n_iter = 100, cv = kfold_count, verbose=2, random_state=42, n_jobs = -1)
# # Fit the random search model
# rf_random.fit(X_train, y_train)
# print("[...] Random search done, best parameters: ",rf_random.best_params_)
# print("[...] Test against base model")
# base_model = RandomForestClassifier(random_state=0, n_jobs=-1)
# base_model.fit(X_train, y_train)
# base_accuracy = evaluate(base_model, X_test, y_test)
# best_random = rf_random.best_estimator_
# random_accuracy = evaluate(best_random, X_test, y_test)

# print('Improvement of {:0.2f}%.'.format( 100 * (random_accuracy - base_accuracy) / base_accuracy))

# Split and train/validate for each fold
kf = StratifiedKFold(n_splits=kfold_count)
tot_acc = 0
#clf = RandomForestClassifier(random_state=0, n_jobs=-1,n_estimators=2000, min_samples_leaf=1, min_samples_split=5, max_features="sqrt", max_depth=10, bootstrap=True)
clf = RandomForestClassifier(random_state=0, n_jobs=-1)
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
    
    print("Accuracy of batch {} = {}%".format(idx, acc))

print("Mean accuracy = {}%".format(np.mean(accuracies)))
print("Variance accuracy = {}%".format(np.var(accuracies)))


# Show importance of each feature (in the array returned by record_to_features())
print_feature_importances_(clf.feature_importances_)

print(f"Accuracy on test data: {clf.score(data_test, target_test)*100}%")

