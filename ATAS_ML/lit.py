import streamlit as st
import numpy as np
import joblib

# Load the saved model and scaler
def load_model():
    try:
        model = joblib.load("random_forest_model.pkl")
        scaler = joblib.load("scaler.pkl")
        return model, scaler
    except Exception as e:
        st.error(f"Error loading model or scaler: {e}")
        return None, None

rf_model, scaler = load_model()

# Function to check anomaly and get probability
def check_anomaly(request_interval, token_length, model_number):
    try:
        input_data = np.array([[request_interval, token_length, model_number]])
        input_scaled = scaler.transform(input_data)
        prediction = rf_model.predict(input_scaled)
        anomaly_prob = rf_model.predict_proba(input_scaled)[0][1] * 100  # Probability of anomaly
        result = "Anomaly" if prediction[0] == 1 else "Normal"
        return result, anomaly_prob
    except Exception as e:
        st.error(f"Error making prediction: {e}")
        return "Error", 0.0

# Streamlit UI
st.title("ATAS(Ai Token Authentication System)")
st.write("Enter the parameters to check for anomalies.")

# Check for query parameters in the URL
query_params = st.query_params

if query_params:
    try:
        request_interval = float(query_params.get("request_interval", 10))
        token_length = int(query_params.get("token_length", 5000))
        model_number = int(query_params.get("model_number", 1))
        
        if rf_model and scaler:
            result, anomaly_prob = check_anomaly(request_interval, token_length, model_number)
            st.write(f"**Result:** {result}")
            st.write(f"**Anomaly Probability:** {anomaly_prob:.2f}%")
    except Exception as e:
        st.error(f"Error processing query parameters: {e}")
else:
    # Interactive UI for manual input
    request_interval = st.number_input("Request Interval (in seconds)", min_value=1, max_value=150, value=10)
    token_length = st.number_input("Token Length", min_value=1, max_value=100000, value=5000)
    model_number = st.selectbox("Model Number", options=[1, 2, 3, 4])

    if st.button("Check for Anomaly"):
        if rf_model and scaler:
            result, anomaly_prob = check_anomaly(request_interval, token_length, model_number)
            st.write(f"**Result:** {result}")
            st.write(f"**Anomaly Probability:** {anomaly_prob:.2f}%")
