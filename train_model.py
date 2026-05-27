import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

print("Loading cleaned data...")

X = pd.read_parquet("data/X_clean.parquet")
y = pd.read_parquet("data/y_clean.parquet")["Label"]

print("Data loaded")
print("Shape:", X.shape)

print("\nSplitting train and test sets...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training Random Forest model...")

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Model training complete")

print("\nMaking predictions...")

y_pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nSaving model...")

joblib.dump(model, "models/ids_model.pkl")

print("Model saved to models/ids_model.pkl")