import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Load dataset
df = pd.read_csv("dataset.csv")

# Drop non-numeric columns
df = df.select_dtypes(include=[np.number])

# Handle missing values
df = df.fillna(0)

# Reduce dataset size
df = df.sample(n=5000, random_state=42)

# Normalize data
scaler = StandardScaler()
X = scaler.fit_transform(df)

# Train model
model = IsolationForest(contamination=0.05)
model.fit(X)

# Save model
pickle.dump(model, open("model.pkl", "wb"))

# Save scaler
pickle.dump(scaler, open("scaler.pkl", "wb"))

print("Model trained successfully!")