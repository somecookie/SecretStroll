#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import pathlib
import csv
import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from scipy import stats

captures_folders = ["captures_sacha", "captures_ricardo", "captures_sacha_2"]
ipv4_regex = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
cell_count = 100
seed = 0
kfold_count = 10


# In[ ]:


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
    return incoming_packets_count(df) / total_packet_count(df);

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
    ]


# In[ ]:


def preprocess_record(df):
    # Remove ARP packets:
    df = df[df['Protocol'] != 'ARP']
    
    return df


# In[ ]:


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


# In[ ]:


# Get records list
records = get_records(captures_folders)


# In[ ]:


# Clean up data
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


# In[ ]:


# Create dataset
X = []
y = []
for cell_id, cell_records in records.items():
    for idx, cell_record in enumerate(cell_records):
        X.append(record_to_features(cell_record))
        y.append(cell_id)

# Shufle dataset
random.seed(seed)
random.shuffle(X)
random.seed(seed)
random.shuffle(y)

X = np.array(X)
y = np.array(y)


# In[ ]:


# Split and train/validate for each fold
kf = StratifiedKFold(n_splits=kfold_count)
tot_acc = 0
clf = RandomForestClassifier(random_state=0, n_jobs=-1)
for idx, (train_index, test_index) in enumerate(kf.split(X, y), 1):
    X_train, y_train = X[train_index], y[train_index]
    X_validation, y_validation = X[test_index], y[test_index]
    
    # Train model
    clf.fit(X_train, y_train)

    # Predict on validation data
    acc = clf.score(X_validation, y_validation) * 100
    tot_acc = tot_acc + acc
    
    print("Accuracy of batch {} = {}%".format(idx, acc))

tot_acc = tot_acc / kfold_count
print("Mean accuracy = {}%".format(tot_acc))


# In[ ]:


# Show importance of each feature (in the array returned by record_to_features())
print(clf.feature_importances_)

