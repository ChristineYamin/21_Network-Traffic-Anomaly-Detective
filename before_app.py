from io import StringIO

from pathlib import Path

import json

import re



import joblib

import numpy as np

import pandas as pd

import streamlit as st

from sklearn.metrics import confusion_matrix





def read_zeek_log(text):

    """Read JSON-lines or tab-separated Zeek conn logs, including IoT-23 labels."""

    text = text.lstrip("\ufeff").strip()

    if not text:

        raise ValueError("The uploaded log is empty.")

    if text.startswith("{"):

        records = []

        for number, line in enumerate(text.splitlines(), 1):

            if not line.strip():

                continue

            record = json.loads(line)

            if not isinstance(record, dict):

                raise ValueError(f"JSON line {number} must contain one connection object.")

            records.append(record)

        frame = pd.DataFrame(records)

    else:

        columns = None

        records = []

        for number, line in enumerate(text.splitlines(), 1):

            if line.startswith("#separator") and line.split()[-1] != r"\x09":

                raise ValueError("This reader supports tab-separated Zeek logs and JSON-lines logs.")

            if line.startswith("#fields"):

                columns = line.split()[1:]

                if len(columns) != len(set(columns)):

                    raise ValueError("The log has duplicate column names.")

            elif line and not line.startswith("#"):

                if columns is None:

                    raise ValueError("The Zeek log needs a #fields header.")

                # IoT-23 appends labels with spaces; ordinary conn fields use tabs.

                values = re.split(r"\s+", line.strip())

                if len(values) != len(columns):

                    raise ValueError(f"Log line {number} has {len(values)} fields; expected {len(columns)}.")

                records.append(values)

        if columns is None:

            raise ValueError("No #fields header was found.")

        frame = pd.DataFrame(records, columns=columns)

    if frame.empty:

        raise ValueError("No connection records were found.")

    return frame.replace({"-": np.nan, "(empty)": np.nan})





def prepare_clues(connections, numeric_columns, text_columns, allow_missing):

    required = numeric_columns + text_columns

    connections = connections.copy()

    if allow_missing:

        # Zeek JSON omits unset optional fields instead of writing a dash.

        for column in ["duration", "orig_bytes", "resp_bytes", "service"]:

            if column in required and column not in connections.columns:

                connections[column] = np.nan

    missing = [column for column in required if column not in connections.columns]

    if missing:

        raise ValueError("Missing required columns: " + ", ".join(missing))

    clues = connections[required].copy()

    for column in numeric_columns:

        original = clues[column]

        converted = pd.to_numeric(original, errors="coerce")

        if (original.notna() & converted.isna()).any():

            raise ValueError(f"Column '{column}' contains non-numeric values.")

        if np.isinf(converted.to_numpy(dtype=float)).any():

            raise ValueError(f"Column '{column}' contains infinite values.")

        if (converted.dropna() < 0).any():

            raise ValueError(f"Column '{column}' contains negative measurements.")

        clues[column] = converted

    for column in text_columns:

        clues[column] = clues[column].map(lambda value: str(value) if pd.notna(value) else np.nan)

    if not allow_missing and clues.isna().any().any():

        raise ValueError("The UNSW model expects complete clues. This file contains missing values.")

    return clues





def known_answers(connections, source):

    if "label" not in connections.columns:

        return None

    normalized = connections["label"].astype("string").str.strip().str.lower()

    mapping = {"0": 0, "1": 1, "0.0": 0, "1.0": 1} if source == "UNSW-NB15 CSV" else {"benign": 0, "malicious": 1}

    actual = normalized.map(mapping)

    if actual.isna().any():

        return None

    return actual.astype(int)





@st.cache_resource

def load_bundle(path):

    return joblib.load(path)









def main():

    st.set_page_config(page_title="Network Traffic Anomaly Detective", page_icon="🛡️", layout="wide")

    st.title("🛡️ Network Traffic Anomaly Detective")

    st.write("Analyze recorded connections and build a queue of possible warnings for review.")

    st.info("Warnings need human review. A flagged connection is not a confirmed attack; an unflagged connection is not guaranteed safe.")



    mode = st.radio("Get started", ["Try demo", "Upload my data"], horizontal=True)
    demo_mode = mode == "Try demo"
    if demo_mode:
        source = "Zeek connection log"
        st.caption("Explore a bundled sample of recorded Zeek traffic. No upload needed.")
        if not st.button("Run demo", type="primary"):
            return
    else:
        source = st.radio("Connection format", ["UNSW-NB15 CSV", "Zeek connection log"], horizontal=True)

    is_zeek = source == "Zeek connection log"

    model_name = "zeek_detector.joblib" if is_zeek else "network_detector.joblib"

    model_path = Path(__file__).parent / "models" / model_name

    if not model_path.is_file():

        st.error(f"Missing model file: models/{model_name}")

        st.stop()

    try:

        saved = load_bundle(str(model_path))

    except Exception as error:

        st.error(f"Could not load the saved model: {error}")

        st.stop()



    if is_zeek:

        st.caption("Supports conn.log with a #fields header, IoT-23 conn.log.labeled, and JSON-lines connection logs. This prototype was evaluated on two separate IoT-23 captures; it does not collect live traffic.")

        file_types = ["log", "labeled", "json", "jsonl", "ndjson"]

    else:

        st.caption("Use a CSV containing the original UNSW-NB15 connection columns.")

        file_types = ["csv"]

    if demo_mode:
        demo_path = Path(__file__).parent / "demo_data" / "capture_8_1.log"
        if not demo_path.is_file():
            st.error("Demo file missing. Put capture_8_1.log in the demo_data folder beside app.py.")
            return
    else:
        uploaded = st.file_uploader("Upload recorded network connections", type=file_types, key=source)
        if uploaded is None:
            return

    try:
        if demo_mode:
            text = demo_path.read_text(encoding="utf-8-sig")
        else:
            text = uploaded.getvalue().decode("utf-8-sig")
        connections = read_zeek_log(text) if is_zeek else pd.read_csv(StringIO(text))

        if connections.empty:

            raise ValueError("The file contains no connections.")

        if connections.columns.duplicated().any():

            raise ValueError("The file contains duplicate column names.")

        if is_zeek:

            numeric_columns = saved["numeric_features"]

            text_columns = saved["categorical_features"]

        else:

            text_columns = saved["text_columns"]

            numeric_columns = [column for column in saved["input_columns"] if not any(column.startswith(f"{name}_") for name in text_columns)]

        clues = prepare_clues(connections, numeric_columns, text_columns, allow_missing=is_zeek)

    except (OSError, ValueError, UnicodeError, pd.errors.ParserError) as error:

        st.error(f"Could not read these connections: {error}")

        st.stop()



    with st.spinner("Analyzing connections…"):

        if is_zeek:

            model = saved["pipeline"]

            model_input = clues

        else:

            model = saved["model"]

            model_input = pd.get_dummies(clues, columns=text_columns, dtype="int8").reindex(columns=saved["input_columns"], fill_value=0)

        try:

            attack_column = list(model.classes_).index(1)

            scores = model.predict_proba(model_input)[:, attack_column]

        except (ValueError, TypeError, KeyError) as error:

            st.error(f"The model could not analyze this file: {error}")

            st.stop()



    threshold = float(saved.get("warning_threshold", 0.5))

    flagged = scores >= threshold

    high_priority = flagged & (scores >= max(0.7, threshold))

    other_count = int(flagged.sum() - high_priority.sum())

    total, warnings, higher = st.columns(3)

    total.metric("Connections analyzed", f"{len(connections):,}")

    warnings.metric("Connections needing review", f"{flagged.sum():,}")

    higher.metric("Higher priority warnings", f"{high_priority.sum():,}")

    st.caption(f"Warning threshold: {threshold:g}. Other warnings: {other_count:,}. Model scores are not calibrated real-world attack probabilities.")



    results = connections.drop(columns=["label", "attack_cat", "detailed-label", "detailed_label"], errors="ignore").copy()

    results["model_score"] = scores.round(3)

    results["needs_review"] = flagged

    results["review_priority"] = np.where(high_priority, "Higher priority", np.where(flagged, "Review", "No warning"))

    review_table = results.loc[flagged].sort_values("model_score", ascending=False)

    st.subheader("Connections to review")

    st.caption("Showing up to 100 warnings. The download includes every flagged connection.")

    st.dataframe(review_table.head(100), use_container_width=True)

    st.download_button("Download connections to review", review_table.to_csv(index=False).encode("utf-8"), "connections_to_review.csv", "text/csv")



    actual = known_answers(connections, source)

    if actual is not None:

        tn, fp, fn, tp = confusion_matrix(actual, flagged.astype(int), labels=[0, 1]).ravel()

        with st.expander("Model evaluation — labeled data only"):

            st.write(f"Malicious connections caught: **{tp:,}**")

            st.write(f"Malicious connections missed: **{fn:,}**")

            st.write(f"False alarms: **{fp:,}**")

            st.write(f"Normal connections left alone: **{tn:,}**")

            if tn + fp:

                st.write(f"False-alarm rate: **{100 * fp / (tn + fp):.3f}%**")

            if tp + fn:

                st.write(f"Attack recall: **{100 * tp / (tp + fn):.2f}%**")

    elif "label" in connections.columns:

        st.caption("Evaluation skipped: labels are missing or contain unsupported values. Predictions still use connection clues only.")



    protocol_summary = results.groupby("proto")["needs_review"].agg(connections="size", warnings="sum")

    protocol_summary = protocol_summary.loc[protocol_summary["connections"] >= 50].copy()

    st.subheader("Warning rate by protocol (%)")

    if protocol_summary.empty:

        st.caption("This chart needs at least 50 connections for a protocol.")

    else:

        protocol_summary["warning_rate"] = 100 * protocol_summary["warnings"] / protocol_summary["connections"]

        st.caption("Only protocols with at least 50 connections are shown. Warning rate is not the same as false-alarm rate.")

        st.bar_chart(protocol_summary["warning_rate"].sort_values(ascending=False).head(10))





if __name__ == "__main__":

    main()
