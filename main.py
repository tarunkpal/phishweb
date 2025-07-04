import streamlit as st
import joblib
from feature_extractor import extract_features

# Load the model
model = joblib.load('model.pkl')

st.title("Phishing URL Detection")
st.markdown("Enter a URL below to detect whether it's **phishing** or **benign**.")

# URL input
url = st.text_input("Enter a URL:", "http://example.com")

if st.button("Predict"):
    if url:
        features = extract_features(url)

        if features:
            # Reshape the feature vector (remove URL and label if present)
            # Assuming features[1:-1] are the real numeric features
            input_vector = [features[1:-1]]  # Must be 2D for sklearn

            prediction = model.predict(input_vector)[0]
            label = "Phishing" if prediction == 1 else "Benign"

            st.success(f"Prediction: **{label}**")
        else:
            st.error("Failed to extract features. Check the URL.")
    else:
        st.warning("Please enter a URL.")
