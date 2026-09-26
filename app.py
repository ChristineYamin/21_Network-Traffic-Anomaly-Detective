from pathlib import Path
import joblib
import streamlit as st

st.set_page_config(page_title="Network Traffic Anomaly Detective", page_icon="🛡️")

model_path = Path(__file__).parent / "models" / "network_detector.joblib"
saved = joblib.load(model_path)

st.title("🛡️ Network Traffic Anomaly Detective")
st.write("Explore network connections and review possible attack warnings.")
st.info(
    "Predictions are warnings for human review. "
    "The model can flag normal connections by mistake."
)

st.success("Saved model loaded successfully.")

st.subheader("Upload network connections")

uploaded_file = st.file_uploader(
    "Choose a CSV with UNSW-NB15 connection columns",
    type="csv"
)

if uploaded_file is not None:
    import pandas as pd

    connections = pd.read_csv(uploaded_file)

    st.write(f"Loaded {len(connections):,} connections.")
    st.dataframe(connections.head(10), use_container_width=True)