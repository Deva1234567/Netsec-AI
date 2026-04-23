# scripts/predict.py
import os
import pickle
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Configure logger
logger = logging.getLogger(__name__)

# Define paths for model and scaler
MODEL_DIR = r"C:\Users\devan\Desktop\Project\IDS project\models"
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# Load model and scaler with file existence checks
model = None
scaler = None

if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        logger.info("Model loaded successfully.")
        # Verify model type and classes
        if not isinstance(model, RandomForestClassifier):
            logger.error("Loaded model is not a RandomForestClassifier.")
            model = None
        else:
            if hasattr(model, 'classes_'):
                logger.info(f"Model has {len(model.classes_)} classes: {model.classes_}")
            else:
                logger.error("Model does not have 'classes_' attribute.")
                model = None
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        logger.error("This error is likely due to a compatibility issue. Please recreate model.pkl using your current Python and scikit-learn versions.")
else:
    logger.error(f"Model file not found at {MODEL_PATH}")

if os.path.exists(SCALER_PATH):
    try:
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        logger.info("Scaler loaded successfully.")
        # Verify scaler type
        if not isinstance(scaler, StandardScaler):
            logger.error("Loaded scaler is not a StandardScaler.")
            scaler = None
    except Exception as e:
        logger.error(f"Error loading scaler: {str(e)}")
        logger.error("This error is likely due to a compatibility issue (e.g., 'STACK_GLOBAL requires str'). Please recreate scaler.pkl using your current Python and scikit-learn versions.")
        logger.error("""
import os
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np

# Create dummy data to train the model and fit the scaler
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
model_dir = "C:\\\\Users\\\\devan\\\\Desktop\\\\Project\\\\IDS project\\\\models"
os.makedirs(model_dir, exist_ok=True)
with open(os.path.join(model_dir, "model.pkl"), "wb") as f:
    pickle.dump(model, f)
with open(os.path.join(model_dir, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)
        """)
else:
    logger.error(f"Scaler file not found at {SCALER_PATH}")

def extract_features(domain, packet_indicators=None, ssl_result=None, scan_result=None):
    """
    Extract numerical features from the domain and analysis results for prediction.
    Returns a tuple of (features array, ssl_failed boolean).
    """
    try:
        # Initialize default values
        features = {
            "domain_length": len(domain) if domain else 0,
            "ssl_expired": 0,
            "ssl_hostname_match": 1,
            "open_ports_count": 0,
            "packet_suspicious": 0
        }
        ssl_failed = False

        # Extract features from SSL result
        if isinstance(ssl_result, dict):
            if "error" in ssl_result:
                logger.warning(f"SSL check failed for {domain}: {ssl_result['error']}")
                ssl_failed = True
                features["ssl_expired"] = 1  # Treat as expired
                features["ssl_hostname_match"] = 0  # Treat as mismatch
            else:
                features["ssl_expired"] = 1 if ssl_result.get("expired", False) else 0
                features["ssl_hostname_match"] = 1 if ssl_result.get("hostname_match", True) else 0
        else:
            logger.warning("SSL result invalid or missing, using default values.")
            ssl_failed = True
            features["ssl_expired"] = 1
            features["ssl_hostname_match"] = 0

        # Extract features from scan result
        if isinstance(scan_result, dict) and "ports" in scan_result:
            features["open_ports_count"] = len(scan_result["ports"])
        else:
            logger.warning("Scan result invalid or missing, using default values.")

        # Extract features from packet indicators
        if isinstance(packet_indicators, dict):
            features["packet_suspicious"] = 1 if packet_indicators.get("suspicious", False) else 0
        else:
            logger.warning("Packet indicators invalid or missing, using default values.")

        logger.debug(f"Extracted features for {domain}: {features}, SSL failed: {ssl_failed}")
        feature_array = np.array([[
            features["domain_length"],
            features["ssl_expired"],
            features["ssl_hostname_match"],
            features["open_ports_count"],
            features["packet_suspicious"]
        ]])
        return feature_array, ssl_failed
    except Exception as e:
        logger.error(f"Error extracting features for {domain}: {str(e)}")
        return np.array([[0, 1, 0, 0, 0]]), True  # Default to unsafe features if extraction fails

def predict_threat(domain, packet_indicators=None, ssl_result=None, scan_result=None):
    """
    Predict the threat level for a given domain using the loaded model.
    If SSL check fails, overrides prediction to 'Malware' (Unsafe).
    Returns a tuple of (prediction_label, probabilities).
    Prediction labels: "Safe", "Low Risk", "Malware".
    """
    try:
        if model is None or scaler is None:
            logger.error("Model or scaler not loaded, cannot predict.")
            return "Error: Model or scaler not loaded", None

        # Extract features and check if SSL failed
        features, ssl_failed = extract_features(domain, packet_indicators, ssl_result, scan_result)

        # If SSL check failed, override prediction to 'Malware' (Unsafe)
        if ssl_failed:
            logger.info(f"SSL check failed for {domain}, overriding prediction to 'Malware' (Unsafe).")
            return "Malware", {"Safe": 0.0, "Low Risk": 0.0, "Malware": 1.0}

        # Scale the features
        features_scaled = scaler.transform(features)

        # Predict
        prediction = model.predict(features_scaled)[0]
        probabilities = model.predict_proba(features_scaled)[0]

        # Map prediction to label dynamically based on model's classes
        label_map = {0: "Safe", 1: "Low Risk", 2: "Malware"}
        if hasattr(model, 'classes_'):
            num_classes = len(model.classes_)
            logger.info(f"Model has {num_classes} classes: {model.classes_}")
            if num_classes != len(label_map):
                logger.warning(f"Model has {num_classes} classes, but label_map expects 3. Adjusting label mapping.")
        else:
            logger.warning("Model does not have 'classes_' attribute. Assuming 3 classes.")
            num_classes = 3

        # Ensure prediction is within bounds
        if prediction not in label_map:
            logger.error(f"Prediction {prediction} not in label_map: {label_map}")
            return "Error: Invalid prediction value", None

        prediction_label = label_map.get(prediction, "Unknown")

        # Create probability dictionary dynamically
        prob_dict = {}
        for i in range(len(probabilities)):
            label = label_map.get(i, f"Class_{i}")
            prob_dict[label] = probabilities[i]

        logger.info(f"Prediction for {domain}: {prediction_label}, Probabilities: {prob_dict}")
        return prediction_label, prob_dict
    except Exception as e:
        logger.error(f"Prediction error for {domain}: {str(e)}")
        return f"Error: {str(e)}", None