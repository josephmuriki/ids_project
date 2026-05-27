import pandas as pd

X = pd.read_parquet("data/X_clean.parquet")
y = pd.read_parquet("data/y_clean.parquet")

X["Label"] = y["Label"]

# Get attack rows
attack_df = X[X["Label"] == 1].head(10)

attack_df = attack_df.drop(columns=["Label"])

attack_df.to_csv("ddos_test.csv", index=False)

print("ddos_test.csv created successfully")