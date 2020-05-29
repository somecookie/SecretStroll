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

captures_folders = ["captures"]
ipv4_regex = '^172\.19\.0\.3|172\.18\.0\.2$'
cell_count = 100
seed = 0

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


def nbr_bytes_data_sent(df):
    packets = df[df['Source'].str.contains(ipv4_regex, regex=True)]
    data = packets[packets["Info"].str.contains("Application Data")]
    return data["Length"].sum()


def nbr_bytes_data_received(df):
    packets = df[df['Destination'].str.contains(ipv4_regex, regex=True)]
    data = packets[packets["Info"].str.contains("Application Data")]
    return data["Length"].sum()


def avg_bytes_data_sent(df):
    packets = df[df['Source'].str.contains(ipv4_regex, regex=True)]
    data = packets[packets["Info"].str.contains("Application Data")]
    return data["Length"].mean()


def avg_bytes_data_received(df):
    packets = df[df['Destination'].str.contains(ipv4_regex, regex=True)]
    data = packets[packets["Info"].str.contains("Application Data")]
    return data["Length"].mean()

def nbr_reassembled_packets(df):
    packets = df[df["Info"].str.contains("[TCP segment of a reassembled PDU]")]
    return len(packets)

def nbr_TCP_packets(df):
    packets = df[df["Protocol"] == "TCP"]
    return len(packets)

def nbr_TLS_packets(df):
    packets = df[df["Protocol"].str.contains("TLS")]
    return len(packets)

def time_of_first_response(df):
    packets = df[df['Destination'].str.contains(ipv4_regex, regex=True)]
    data = packets[packets["Info"].str.contains("Application Data")]
    return data["Time"].iloc[[0]]
    


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
        average_time_between_outgoing_packets(df),
        nbr_bytes_data_sent(df),
        nbr_bytes_data_received(df),
        avg_bytes_data_sent(df),
        avg_bytes_data_received(df),
        nbr_reassembled_packets(df),
        nbr_TCP_packets(df),
        nbr_TLS_packets(df),
        time_of_first_response(df)
    ]


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
                # Remove the _ws.col. prefix in the columns name
                df = df.rename(lambda x: x.split('.')[-1], axis='columns')
                records[cell].append(preprocess_record(df))
    return records




def get_dataset():
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
        records[cell] = [rec for idx, rec in enumerate(
            cell_records) if should_select.iat[idx, 0]]

    print("[...] Creating dataset")
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

    return X, y
