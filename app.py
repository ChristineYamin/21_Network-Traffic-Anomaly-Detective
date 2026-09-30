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
    text = text.lstrip('\ufeff').strip()
    if not text:
        raise ValueError('The uploaded log is empty.')
    if text.startswith('{'):
        records = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f'JSON line {number} must contain one connection object.')
            records.append(record)
        frame = pd.DataFrame(records)
    else:
        columns = None
        records = []
        for number, line in enumerate(text.splitlines(), 1):
            if line.startswith('#separator') and line.split()[-1] != '\\x09':
                raise ValueError('This reader supports tab-separated Zeek logs and JSON-lines logs.')
            if line.startswith('#fields'):
                columns = line.split()[1:]
                if len(columns) != len(set(columns)):
                    raise ValueError('The log has duplicate column names.')
            elif line and (not line.startswith('#')):
                if columns is None:
                    raise ValueError('The Zeek log needs a #fields header.')
                values = re.split('\\s+', line.strip())
                if len(values) != len(columns):
                    raise ValueError(f'Log line {number} has {len(values)} fields; expected {len(columns)}.')
                records.append(values)
        if columns is None:
            raise ValueError('No #fields header was found.')
        frame = pd.DataFrame(records, columns=columns)
    if frame.empty:
        raise ValueError('No connection records were found.')
    return frame.replace({'-': np.nan, '(empty)': np.nan})

def prepare_clues(connections, numeric_columns, text_columns, allow_missing):
    required = numeric_columns + text_columns
    connections = connections.copy()
    if allow_missing:
        for column in ['duration', 'orig_bytes', 'resp_bytes', 'service']:
            if column in required and column not in connections.columns:
                connections[column] = np.nan
    missing = [column for column in required if column not in connections.columns]
    if missing:
        raise ValueError('Missing required columns: ' + ', '.join(missing))
    clues = connections[required].copy()
    for column in numeric_columns:
        original = clues[column]
        converted = pd.to_numeric(original, errors='coerce')
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
        raise ValueError('The UNSW model expects complete clues. This file contains missing values.')
    return clues

def known_answers(connections, source):
    if 'label' not in connections.columns:
        return None
    normalized = connections['label'].astype('string').str.strip().str.lower()
    mapping = {'0': 0, '1': 1, '0.0': 0, '1.0': 1} if source == 'UNSW-NB15 CSV' else {'benign': 0, 'malicious': 1}
    actual = normalized.map(mapping)
    if actual.isna().any():
        return None
    return actual.astype(int)

@st.cache_resource
def load_bundle(path):
    return joblib.load(path)


STATUS_COLORS = {
    "Needs review": "#dc2626", "No warning": "#16a34a",
    "False alarm": "#f59e0b", "Missed attack": "#9333ea",
}


def traffic_observations(connections, is_zeek):
    """Describe measured patterns, not causal explanations of the model."""
    frame = connections.reset_index(drop=True)
    notes = [[] for _ in range(len(frame))]
    burst_counts = np.zeros(len(frame), dtype=int)
    keys = ["ts", "id.orig_h", "id.resp_h"]
    if is_zeek and all(key in frame for key in keys):
        times = pd.to_numeric(frame["ts"], errors="coerce")
        valid = times.notna() & np.isfinite(times) & frame[keys[1:]].notna().all(axis=1)
        usable = frame.loc[valid, keys[1:]].copy()
        usable["timestamp"] = times.loc[valid]
        for _, group in usable.groupby(keys[1:], sort=False):
            ordered = group.sort_values("timestamp")
            stamps = ordered["timestamp"].to_numpy(dtype=float)
            # Include both window boundaries and all simultaneous records.
            counts = np.searchsorted(stamps, stamps, side="right") - np.searchsorted(stamps, stamps - 120, side="left")
            for index, count in zip(ordered.index, counts):
                burst_counts[index] = count
                if count >= 100:
                    notes[index].append(f"This device made {count:,} connections to the same destination in the preceding 2 minutes (including this connection).")
    outgoing = "orig_pkts" if is_zeek else "spkts"
    incoming = "resp_pkts" if is_zeek else "dpkts"
    if outgoing in frame and incoming in frame:
        sent = pd.to_numeric(frame[outgoing], errors="coerce")
        received = pd.to_numeric(frame[incoming], errors="coerce")
        for index in frame.index[(sent > 0) & (received == 0)]:
            notes[index].append(f"{sent[index]:g} packets sent; no reply packets recorded.")
    if is_zeek and "conn_state" in frame:
        states = frame["conn_state"].astype("string")
        for index in frame.index[states.eq("S0").fillna(False)]:
            notes[index].append("Connection attempt recorded with no reply (Zeek state S0).")
        for index in frame.index[states.eq("REJ").fillna(False)]:
            notes[index].append("Connection attempt rejected (Zeek state REJ).")
    return [" ".join(items) if items else "No selected traffic pattern detected; inspect the connection details." for items in notes], burst_counts


def connection_statuses(flagged, actual):
    statuses = np.where(flagged, "Needs review", "No warning").astype(object)
    if actual is not None:
        labels = actual.to_numpy()
        statuses[flagged & (labels == 0)] = "False alarm"
        statuses[(~flagged) & (labels == 1)] = "Missed attack"
    return statuses


def color_connection(row):
    color = STATUS_COLORS[row["status"]]
    return [f"background-color: {color}; color: white" if column == "status" else "" for column in row.index]


def main():
    st.set_page_config(page_title='Network Traffic Anomaly Detective', page_icon='🛡️', layout='wide')
    st.title('🛡️ Network Traffic Anomaly Detective')
    st.write('Analyze recorded connections and build a queue of possible warnings for review.')
    with st.expander("How it works"):
        st.markdown("""
        Choose **Try demo** or upload your recorded network traffic.

        - 🔴 **Needs review:** the model flagged the connection.
        - 🟢 **No warning:** the model did not flag it.
        - 🟠 **False alarm:** flagged, but the known label says normal.
        - 🟣 **Missed attack:** not flagged, but the known label says malicious.

        Orange and purple require known labels.

        **Model score** determines whether a connection is flagged.
        **Observed traffic** describes patterns in the log, such as
        missing replies; it does not explain the model’s exact reasoning.
        """)
    st.info('Warnings need human review. A flagged connection is not a confirmed attack; an unflagged connection is not guaranteed safe.')
    mode = st.radio('Get started', ['Try demo', 'Upload my data'], horizontal=True)
    demo_mode = mode == 'Try demo'
    if demo_mode:
        source = 'Zeek connection log'
        st.caption('Explore a bundled sample of recorded Zeek traffic. No upload needed.')
        if st.button('Run demo', type='primary'):
            st.session_state['demo_started'] = True
        if not st.session_state.get('demo_started', False):
            return
    else:
        source = st.radio('Connection format', ['UNSW-NB15 CSV', 'Zeek connection log'], horizontal=True)
    is_zeek = source == 'Zeek connection log'
    model_name = 'zeek_detector.joblib' if is_zeek else 'network_detector.joblib'
    model_path = Path(__file__).parent / 'models' / model_name
    if not model_path.is_file():
        st.error(f'Missing model file: models/{model_name}')
        st.stop()
    try:
        saved = load_bundle(str(model_path))
    except Exception as error:
        st.error(f'Could not load the saved model: {error}')
        st.stop()
    if is_zeek:
        if not demo_mode:
            st.caption('Supports conn.log with a #fields header, IoT-23 conn.log.labeled, and JSON-lines connection logs. This prototype was evaluated on two separate IoT-23 captures; it does not collect live traffic.')
        file_types = ['log', 'labeled', 'json', 'jsonl', 'ndjson']
    else:
        st.caption('Use a CSV containing the original UNSW-NB15 connection columns.')
        file_types = ['csv']
    if demo_mode:
        demo_path = Path(__file__).parent / 'demo_data' / 'capture_8_1.log'
        if not demo_path.is_file():
            st.error('Demo file missing. Put capture_8_1.log in the demo_data folder beside app.py.')
            return
    else:
        uploaded = st.file_uploader('Upload recorded network connections', type=file_types, key=source)
        if uploaded is None:
            return
    try:
        if demo_mode:
            text = demo_path.read_text(encoding='utf-8-sig')
        else:
            text = uploaded.getvalue().decode('utf-8-sig')
        connections = read_zeek_log(text) if is_zeek else pd.read_csv(StringIO(text))
        if connections.empty:
            raise ValueError('The file contains no connections.')
        if connections.columns.duplicated().any():
            raise ValueError('The file contains duplicate column names.')
        if is_zeek:
            numeric_columns = saved['numeric_features']
            text_columns = saved['categorical_features']
        else:
            text_columns = saved['text_columns']
            numeric_columns = [column for column in saved['input_columns'] if not any((column.startswith(f'{name}_') for name in text_columns))]
        clues = prepare_clues(connections, numeric_columns, text_columns, allow_missing=is_zeek)
    except (OSError, ValueError, UnicodeError, pd.errors.ParserError) as error:
        st.error(f'Could not read these connections: {error}')
        st.stop()
    with st.spinner('Analyzing connections…'):
        if is_zeek:
            model = saved['pipeline']
            model_input = clues
        else:
            model = saved['model']
            model_input = pd.get_dummies(clues, columns=text_columns, dtype='int8').reindex(columns=saved['input_columns'], fill_value=0)
        try:
            attack_column = list(model.classes_).index(1)
            scores = model.predict_proba(model_input)[:, attack_column]
        except (ValueError, TypeError, KeyError) as error:
            st.error(f'The model could not analyze this file: {error}')
            st.stop()
    threshold = float(saved.get('warning_threshold', 0.5))
    flagged = scores >= threshold
    high_priority = flagged & (scores >= max(0.7, threshold))
    other_count = int(flagged.sum() - high_priority.sum())
    actual = known_answers(connections, source)
    statuses = connection_statuses(flagged, actual)
    observations, burst_counts = traffic_observations(connections, is_zeek)

    st.subheader("Traffic overview")
    cols = st.columns(4)
    cols[0].metric("Connections analyzed", f"{len(connections):,}")
    cols[1].metric("🔴 Needs review", f"{np.count_nonzero(statuses == 'Needs review'):,}")
    cols[2].metric("🟢 No warning", f"{np.count_nonzero(statuses == 'No warning'):,}")
    cols[3].metric("🟠 False alarms", f"{np.count_nonzero(statuses == 'False alarm'):,}" if actual is not None else "Unknown")
    counts = [{"status": status, "connections": int(np.count_nonzero(statuses == status))}
              for status in STATUS_COLORS if actual is not None or status in ["Needs review", "No warning"]]
    st.vega_lite_chart(pd.DataFrame(counts), {
        "mark": {"type": "bar", "cornerRadiusEnd": 5},
        "encoding": {
            "x": {"field": "status", "type": "nominal", "sort": list(STATUS_COLORS), "axis": {"title": None, "labelAngle": 0}},
            "y": {"field": "connections", "type": "quantitative", "title": "Connections"},
            "color": {"field": "status", "type": "nominal", "scale": {"domain": list(STATUS_COLORS), "range": list(STATUS_COLORS.values())}, "legend": None},
            "tooltip": [{"field": "status", "type": "nominal"}, {"field": "connections", "type": "quantitative", "format": ","}],
        }, "height": 240,
    }, use_container_width=True)
    st.caption("Red: flagged for review. Green: no model warning. Orange: flagged but labeled normal. Purple: labeled attack missed by the model. Categories do not overlap.")
    if actual is None:
        st.caption("False alarms and missed attacks are unknown without complete supported labels.")
    st.caption(f"Total model warnings: {flagged.sum():,}, including {high_priority.sum():,} higher priority and {other_count:,} other warnings. Threshold: {threshold:g}. Scores are not calibrated attack probabilities.")

    results = connections.drop(columns=["label", "attack_cat", "detailed-label", "detailed_label"], errors="ignore").copy()
    results["model_score"] = scores.round(3)
    results["needs_review"] = flagged
    results["status"] = statuses
    results["review_priority"] = np.where(high_priority, "Higher priority", np.where(flagged, "Review", "No warning"))
    results["traffic_observations"] = observations
    if is_zeek and all(key in connections for key in ["ts", "id.orig_h", "id.resp_h"]):
        results["same_destination_connections_2min"] = burst_counts
    results["warning_basis"] = [f"Model score {score:.3f} meets threshold {threshold:g}." if flag else f"Model score {score:.3f} is below threshold {threshold:g}." for score, flag in zip(scores, flagged)]

    st.subheader("Explore connections")
    st.caption("Traffic observations describe recorded behaviour; they are not the model's exact explanation. Repeated connections and missing replies can also occur in normal traffic.")
    selection = st.selectbox("Show", ["Warnings", "All connections"] + [status for status in STATUS_COLORS if status in statuses])
    if selection == "Warnings":
        table = results.loc[flagged]
    elif selection == "All connections":
        table = results
    else:
        table = results.loc[results["status"] == selection]
    table = table.sort_values("model_score", ascending=False)
    first = ["status", "model_score", "traffic_observations", "warning_basis", "review_priority"]
    display = table[first + [column for column in table if column not in first]]
    st.caption(f"Showing {min(100, len(display)):,} of {len(display):,} connections in this view.")
    st.dataframe(
    display.head(100).style.apply(color_connection, axis=1),
    use_container_width=True,
    column_config={
        "status": "Connection status",
        "model_score": "Model score",
        "traffic_observations": "Observed traffic",
        "warning_basis": "Why the model flagged it",
        "review_priority": "Review priority",
        "ts": "Timestamp",
        "id.orig_h": "Source device",
        "id.orig_p": "Source port",
        "id.resp_h": "Destination address",
        "id.resp_p": "Destination port",
        "proto": "Protocol",
        "service": "Service",
        "duration": "Duration (seconds)",
        "orig_pkts": "Packets sent",
        "resp_pkts": "Packets received",
        "orig_bytes": "Bytes sent",
        "resp_bytes": "Bytes received",
        "conn_state": "Connection state",
        "same_destination_connections_2min": "Connections to same destination in 2 min",
    },
)
    
    st.download_button("Download this view", display.to_csv(index=False).encode("utf-8"), "connection_review.csv", "text/csv")
    if not table.empty:
        with st.expander("Inspect one connection", expanded=True):
            positions = list(range(min(100, len(table))))
            chosen = st.selectbox("Connection", positions, format_func=lambda pos: f"Row {table.index[pos]} · {table.iloc[pos]['status']} · score {table.iloc[pos]['model_score']:.3f}")
            row = table.iloc[chosen]
            message = (
                f"**{row['status']}**\n\n"
                f"{row['warning_basis']}\n\n"
                f"**Observed traffic:** {row['traffic_observations']}"
            )

            if row["status"] == "Needs review":
                st.error(message)
            elif row["status"] == "No warning":
                st.success(message)
            elif row["status"] == "False alarm":
                st.warning(message)
            else:
                st.info(message)
            if row["status"] == "False alarm":
                st.write("The known dataset label is normal, despite the model warning.")
            elif row["status"] == "Missed attack":
                st.write("The known dataset label is malicious, despite the absence of a model warning.")

    actual = known_answers(connections, source)
    if actual is not None:
        tn, fp, fn, tp = confusion_matrix(actual, flagged.astype(int), labels=[0, 1]).ravel()
        with st.expander("Model evaluation — labeled data only"):
            left, right = st.columns(2)

            with left:
                with st.container(border=True):
                    st.metric("🔴 Malicious connections caught", f"{tp:,}")
                with st.container(border=True):
                    st.metric("🟠 False alarms", f"{fp:,}")

            with right:
                with st.container(border=True):
                    st.metric("🟣 Malicious connections missed", f"{fn:,}")
                with st.container(border=True):
                    st.metric("🟢 Normal connections left alone", f"{tn:,}")

            rate, recall = st.columns(2)

            with rate:
                with st.container(border=True):
                    st.metric(
                        "False-alarm rate",
                        f"{100 * fp / (tn + fp):.3f}%"
                        if tn + fp else "N/A",
                    )

            with recall:
                with st.container(border=True):
                    st.metric(
                        "Attack recall",
                        f"{100 * tp / (tp + fn):.2f}%"
                        if tp + fn else "N/A",
                    )


        
    elif 'label' in connections.columns:
        st.caption('Evaluation skipped: labels are missing or contain unsupported values. Predictions still use connection clues only.')
    protocol_summary = results.groupby('proto')['needs_review'].agg(connections='size', warnings='sum')
    protocol_summary = protocol_summary.loc[protocol_summary['connections'] >= 50].copy()
    st.subheader('Warning rate by protocol (%)')
    if protocol_summary.empty:
        st.caption('This chart needs at least 50 connections for a protocol.')
    else:
        protocol_summary['warning_rate'] = 100 * protocol_summary['warnings'] / protocol_summary['connections']
        st.caption('Only protocols with at least 50 connections are shown. Warning rate is not the same as false-alarm rate.')
        st.bar_chart(protocol_summary['warning_rate'].sort_values(ascending=False).head(10))
if __name__ == '__main__':
    main()
