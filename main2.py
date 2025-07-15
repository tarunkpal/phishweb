import streamlit as st
import requests
import re
import json
import pickle
import numpy as np
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, Concatenate, Conv1D, MaxPooling1D, Flatten, Dense
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Constants
URL_MAX_LEN = 180
HTML_MAX_LEN = 2000
EMBED_DIM = 16
URL_VOCAB_SIZE = 76
HTML_VOCAB_SIZE = 321010

def merge_parts(base_filename, output_file):
    part_num = 0
    with open(output_file, 'wb') as outfile:
        while True:
            part_file = f"{base_filename}.part{part_num:03d}"
            if not os.path.exists(part_file):
                break
            with open(part_file, 'rb') as pf:
                outfile.write(pf.read())
            print(f"Merged: {part_file}")
            part_num += 1
            
# Load URL char index
with open("url_char_to_index.json", "r") as f:
    url_char_to_index = json.load(f)

# Load HTML tokenizer
if not os.path.exists("html_tokenizer.pkl"):
        merge_parts("html_tokenizer.pkl", "html_tokenizer.pkl")
with open("html_tokenizer.pkl", "rb") as f:
    html_tokenizer = pickle.load(f)

# Build model
def build_webphish():
    url_input = Input(shape=(URL_MAX_LEN,))
    html_input = Input(shape=(HTML_MAX_LEN,))

    url_embed = Embedding(URL_VOCAB_SIZE, EMBED_DIM)(url_input)
    html_embed = Embedding(HTML_VOCAB_SIZE, EMBED_DIM)(html_input)

    merged = Concatenate(axis=1)([url_embed, html_embed])
    conv = Conv1D(32, 8, activation='relu')(merged)
    pool = MaxPooling1D(2)(conv)
    flat = Flatten()(pool)
    fc1 = Dense(10, activation='relu')(flat)
    fc2 = Dense(10, activation='relu')(fc1)
    out = Dense(1, activation='sigmoid')(fc2)

    model = Model(inputs=[url_input, html_input], outputs=out)
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

model = build_webphish()
model.load_weights("webphish_weights.h5")

# Preprocessing
def preprocess_url(url):
    tokens = [url_char_to_index.get(c, 0) for c in url]
    return pad_sequences([tokens], maxlen=URL_MAX_LEN, padding='post', truncating='post')

def preprocess_html(html):
    tokens = html_tokenizer.texts_to_sequences([html])[0]
    return pad_sequences([tokens], maxlen=HTML_MAX_LEN, padding='post', truncating='post')

# Streamlit UI
st.title("🔒 WebPhish: Phishing Detector")
input_url = st.text_input("Enter a URL (with or without http/https):", "")

if st.button("Detect"):
    if not input_url.strip():
        st.error("Please enter a URL.")
    else:
        try:
            # Normalize URL
            if not input_url.startswith("http"):
                full_url = "http://" + input_url
            else:
                full_url = input_url

            response = requests.get(full_url, timeout=10)
            response.raise_for_status()
            html = response.text

            # Remove protocol
            clean_url = re.sub(r"https?://", "", full_url)

            # Tokenize
            url_seq = preprocess_url(clean_url)
            html_seq = preprocess_html(html)

            # Predict
            pred = model.predict([url_seq, html_seq])[0][0]
            prob = round(float(pred), 4)
            label = "🟥 Phishing" if pred >= 0.5 else "🟩 Legitimate"

            st.markdown(f"**Prediction:** {label}")
            st.markdown(f"**Confidence:** {prob}")

        except Exception as e:
            st.error(f"❌ Failed to fetch HTML: {str(e)}")
