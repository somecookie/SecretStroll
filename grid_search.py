#!/usr/bin/env python
# coding: utf-8

import pathlib
import csv
import pandas as pd
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from scipy import stats
from sklearn.model_selection import train_test_split
from sklearn.model_selection import RandomizedSearchCV, GridSearchCV
from sklearn.model_selection import train_test_split
from dataset import get_dataset
import matplotlib.pyplot as plt

kfold_count = 10

X, y = get_dataset()
print("[...] Data ready")


data_train, data_test, target_train, target_test = train_test_split(
    X, y, test_size=0.3)
print("[...] Data split into training and testing set")

print("[...] Random search on parameters")

# Number of trees in random forest
n_estimators = range(10, 2000, 100)

# Use the random grid to search for best hyperparameters
# First create the base model to tune
rf = RandomForestClassifier()

# Random search of parameters, using 3 fold cross validation,
# search across 100 different combinations, and use all available cores
random_grid = {'n_estimators': n_estimators}
rf_random = GridSearchCV(estimator = rf, param_grid = random_grid, cv = kfold_count, verbose=5, n_jobs = -1)

# Fit the random search model
rf_random.fit(data_train, target_train)
print("[...] Random search done, best parameters: ",rf_random.best_params_)

