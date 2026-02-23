# Phishing Detection - Version A (Changed by Dev A)
# Master branch: minor cleanup
# Feature branch: adding extra documentation

import streamlit as st
import re
import socket
import tldextract
import whois

import requests
from bs4 import BeautifulSoup
from datetime import datetime
import pandas as pd
import joblib

# Load trained model
model = joblib.load("my_model.pkl")

# --- Feature extraction function ---
def extract_features(url):
    feats = {}
    feats['length_url'] = len(url)
    ext = tldextract.extract(url)
    hostname = ext.domain + "." + ext.suffix
    feats['length_hostname'] = len(hostname)

    # IP address present in URL?
    try:
        socket.inet_aton(ext.domain)   # check if domain is an IP
        feats['ip'] = 1
    except:
        feats['ip'] = 0

    # Count symbols
    feats['nb_dots'] = url.count(".")
    feats['nb_qm'] = url.count("?")
    feats['nb_slash'] = url.count("/")
    feats['nb_www'] = url.count("www")

    # Digits ratio
    feats['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url)
    feats['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / len(hostname)

    # TLD in subdomain?
    feats['tld_in_subdomain'] = 1 if ext.suffix in ext.subdomain else 0

    # Prefix-Suffix with '-'
    feats['prefix_suffix'] = 1 if '-' in ext.domain else 0

    # Host word lengths
    words_host = re.split(r'\W+', hostname)
    feats['shortest_word_host'] = min([len(w) for w in words_host if w]) if words_host else 0
    feats['longest_words_raw'] = max([len(w) for w in words_host if w]) if words_host else 0
    feats['avg_word_host'] = sum(len(w) for w in words_host if w)/len(words_host) if words_host else 0

    # Path analysis
    path = url.split(ext.suffix)[-1]
    words_path = re.split(r'\W+', path)
    feats['avg_word_path'] = sum(len(w) for w in words_path if w)/len(words_path) if words_path else 0

    # Suspicious hints
    phish_hints = ["login", "verify", "bank", "update", "free", "bonus", "secure"]
    feats['phish_hints'] = sum(h in url.lower() for h in phish_hints)

    # --- HTML Content (Requests + BeautifulSoup) ---
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        links = soup.find_all('a')
        feats['nb_hyperlinks'] = len(links)

        int_links = [l for l in links if l.get("href") and hostname in l.get("href")]
        feats['ratio_intHyperlinks'] = len(int_links)/len(links) if links else 0

        imgs = soup.find_all('img')
        int_imgs = [i for i in imgs if i.get("src") and hostname in i.get("src")]
        feats['ratio_intMedia'] = len(int_imgs)/len(imgs) if imgs else 0

        # Domain in title?
        title = soup.title.string if soup.title else ""
        feats['domain_in_title'] = 1 if ext.domain.lower() in title.lower() else 0

    except:
        feats['nb_hyperlinks'] = 0
        feats['ratio_intHyperlinks'] = 0
        feats['ratio_intMedia'] = 0
        feats['domain_in_title'] = 0

    # --- Domain age ---
    try:
        w = whois.whois(hostname)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        feats['domain_age'] = (datetime.now() - creation_date).days if creation_date else -1
    except:
        feats['domain_age'] = -1

    # Status dummy (not used in prediction, but required in dataset)
    feats['status'] = -1   # placeholder

    return feats

# --- Streamlit UI ---
st.set_page_config(page_title="Phishing URL Detector", layout="centered")

st.title("🔐 Phishing URL Detector")
st.write("Enter a URL below to check if it's **Phishing** or **Legitimate**.")

# Input box
url = st.text_input("Enter URL: ")

if st.button("🔎 Analyze"):
    # Extract features
    features = extract_features(url)

    # Convert into dataframe for model prediction
    x_new = pd.DataFrame([features])

    # Drop the status column (since model trained without it)
    x_new = x_new.drop(columns=['status'])

    # Predict
    prediction = model.predict(x_new)[0]

    # Show result
    if prediction == 1:
        st.error("⚠️ Phishing Website Detected!")
    else:
        st.success("✅ Legitimate Website")

    # Show extracted features (optional for debugging)
    with st.expander("🔍 Extracted Features"):
        st.json(features)
