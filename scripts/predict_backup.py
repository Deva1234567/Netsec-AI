# Script to recreate model.pkl and scaler.pkl with 3 classes
import os
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np

# Create dummy data to train the model and fit the scaler
# Features: [domain_length, ssl_expired, ssl_hostname_match, open_ports_count, packet_suspicious]
X = np.array([
    [1, 0, 1, 0, 0],   # Example for Safe
    [10, 1, 0, 2, 1],  # Example for Low Risk
    [15, 1, 0, 5, 1]   # Example for Malware
])
y = np.array([0, 1, 2])  # Labels: 0 (Safe), 1 (Low Risk), 2 (Malware)

# Train a simple model
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X, y)

# Create and fit a scaler
scaler = StandardScaler()
scaler.fit(X)

# Save the model and scaler
model_dir = r"C:\Users\devan\Desktop\Project\IDS project\models"
os.makedirs(model_dir, exist_ok=True)
with open(os.path.join(model_dir, "model.pkl"), "wb") as f:
    pickle.dump(model, f)
with open(os.path.join(model_dir, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)

print("Model and scaler recreated successfully with 3 classes.")