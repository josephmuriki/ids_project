import pandas as pd
import numpy as np
import os

print("Script started")

DATA_PATH = "data/CICIDS2017"

files = [f for f in os.listdir(DATA_PATH) if f.endswith(".parquet")]
print("Parquet files found:", len(files))

df_list = []

for file in files:
    print("Loading:", file)
    df = pd.read_parquet(os.path.join(DATA_PATH, file))
    df_list.append(df)

data = pd.concat(df_list, ignore_index=True)

print("Dataset loaded successfully")
print("Shape:", data.shape)

print("\nCleaning data...")

data.replace([np.inf, -np.inf], np.nan, inplace=True)
data.dropna(inplace=True)

print("Shape after removing missing/infinite:", data.shape)

print("\nEncoding labels...")

data["Label"] = data["Label"].astype("category").cat.codes

print("Label encoding complete")

X = data.drop("Label", axis=1)
y = data["Label"]

print("\nFeature matrix shape:", X.shape)
print("Target shape:", y.shape)

print("\nSaving cleaned dataset...")

X.to_parquet("data/X_clean.parquet")
y.to_frame().to_parquet("data/y_clean.parquet")

print("Saved cleaned data successfully")
