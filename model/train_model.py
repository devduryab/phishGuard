import os
import sys
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector import make_features, ML_FEATURE_COLUMNS

# Expected CSV columns:
# url,label
# https://example.com,0
# http://example-test-phishing.example,1

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE_DIR, "data", "urls.csv")
MODEL_OUT = os.path.join(BASE_DIR, "model", "phishing_model.joblib")

df = pd.read_csv(DATA)

X = pd.DataFrame([make_features(u) for u in df["url"]])[ML_FEATURE_COLUMNS]
y = df["label"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

pred = model.predict(X_test)
print(classification_report(y_test, pred))

os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
joblib.dump(model, MODEL_OUT)
print("Saved:", MODEL_OUT)
