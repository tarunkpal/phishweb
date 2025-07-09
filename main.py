import streamlit as st
import joblib
from phishing_feature_extractor import PhishingFeatureExtractor
# Load the model
model = joblib.load('model')
extractor = PhishingFeatureExtractor()
st.title("Phishing URL Detection")
st.markdown("Enter a URL below to detect whether it's **phishing** or **benign**.")

# URL input
url = st.text_input("Enter a URL:", "http://example.com")

if st.button("Predict"):
    if url:
        features = extractor.extract_features(url)
        features = list(features.values())  # Get the feature values, excluding URL and label

        if features:
            # Reshape the feature vector (remove URL and label if present)
            # Assuming features[1:-1] are the real numeric features
            input_vector = [features[1:-1]]  # Must be 2D for sklearn
            input_vector.drop(columns='web_traffic',inplace=True)

            prediction = model.predict(input_vector)[0]
            label = "Phishing" if prediction == 1 else "Benign"

            st.success(f"Prediction: **{label}**")
            st.subheader("Extracted Features:")
            for i, feat in enumerate(features[1:-1]):
                st.text(f"Feature {i+1}: {feat}")
        else:
            st.error("Failed to extract features. Check the URL.")
    else:
        st.warning("Please enter a URL.")
