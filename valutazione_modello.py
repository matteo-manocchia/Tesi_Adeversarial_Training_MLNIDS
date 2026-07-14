import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix, recall_score
import sys
import os
import numpy as np
import warnings
from sklearn.exceptions import UndefinedMetricWarning

if len(sys.argv) < 3:
    print("Usage: python valutazione_modelli.py <nome_modello> <file_input>")
    sys.exit(1)

nome_modello = sys.argv[1]
input_file = sys.argv[2]

model = joblib.load(nome_modello)

df = pd.read_csv(input_file, low_memory=False)

df = df[df.infect.astype(str).str.strip().str.lower() == "true"]
df = df.drop("infect", axis=1)

X_test = df.drop(columns=['Label'])
y_test = df['Label']


# Riordina le colonne in base a quelle che il modello si aspetta
if hasattr(model, 'feature_names_in_'):
    X_test = X_test[model.feature_names_in_]

warnings.filterwarnings("ignore", category=UndefinedMetricWarning)

y_pred = model.predict(X_test)

print(f"{nome_modello}")
print("Classification Report")
print(classification_report(y_test, y_pred, labels=[0, 1], target_names=["Benigni", "Malevoli"]))
print("Confusion Matrix")
print(confusion_matrix(y_test, y_pred, labels=[0, 1]))
tpr = recall_score(y_test, y_pred, pos_label=1)
if 0 in y_test.values:
    tnr = recall_score(y_test, y_pred, pos_label=0, zero_division=0)
else:
    tnr = float('nan')

print(f"TPR: {tpr:.4f}")
print(f"TNR: {tnr:.4f}" if not isinstance(tnr, float) or not np.isnan(tnr) else "TNR: N/A")
