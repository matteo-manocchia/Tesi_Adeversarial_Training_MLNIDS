from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, PredefinedSplit
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import make_scorer, recall_score
import numpy as np
import pandas as pd
import joblib
import sys
import os

if len(sys.argv) < 5:
    print("Usage: python programma.py <training_set> <validation_set> <test set> <out_directoy_model>")
    sys.exit(1)
    

training_set = sys.argv[1]
validation_set = sys.argv[2]
test_set = sys.argv[3]
output_dir = sys.argv[4]


df_training = pd.read_csv(training_set, low_memory=False)
df_validation = pd.read_csv(validation_set, low_memory=False)
df_test = pd.read_csv(test_set, low_memory=False)


X_train = df_training.drop(columns=['Label'])
y_train = df_training['Label']

X_val = df_validation.drop(columns=['Label'])
y_val = df_validation['Label']

X_test = df_test.drop(columns=['Label'])
y_test = df_test['Label']


model = RandomForestClassifier(n_estimators=200, criterion='gini', max_depth=None, min_samples_split=2, 
                                     min_samples_leaf=1, min_weight_fraction_leaf=0.0, max_features='sqrt', 
                                     max_leaf_nodes=None, min_impurity_decrease=0.0, bootstrap=True, oob_score=False, 
                                     n_jobs=2, random_state=0, verbose=0, warm_start=False, class_weight=None,
                                     ccp_alpha=0.0, max_samples=None)


model.fit(X_train, y_train)

print("MODELLO NO PAPER")
y_val_pred = model.predict(X_val)
print("PRESTAZIONI SU VALIDATION SET")
print(classification_report(y_val, y_val_pred, target_names=['Benigno', 'Malevolo']))
print(confusion_matrix(y_val, y_val_pred))

tpr = recall_score(y_val, y_val_pred, pos_label=1)
tnr = recall_score(y_val, y_val_pred, pos_label=0)
print(f"TPR: {tpr:.4f}")
print(f"TNR: {tnr:.4f}")
print()

y_test_pred_baseline = model.predict(X_test)
print("PRESTAZIONI SU  TEST SET")
print(classification_report(y_test, y_test_pred_baseline, target_names=['Benigno', 'Malevolo']))
print(confusion_matrix(y_test, y_test_pred_baseline))
tpr = recall_score(y_test, y_test_pred_baseline, pos_label=1)
tnr = recall_score(y_test, y_test_pred_baseline, pos_label=0)
print(f"TPR: {tpr:.4f}")
print(f"TNR: {tnr:.4f}")
print()

model_filename = os.path.join(output_dir, "paper_model.joblib")
joblib.dump(model, model_filename)
