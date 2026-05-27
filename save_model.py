import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

print("Loading cleaned data...")

X = pd.read_parquet("data/X_clean.parquet")
y = pd.read_parquet("data/y_clean.parquet")["Label"]

print("Splitting data...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Saving model...")

joblib.dump(model, "models/ids_model.pkl")

print("Model saved successfully")
