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

    # Check that the uploaded CSV has the model's original input columns
    text_columns = saved["text_columns"]

    numeric_columns = [
        column for column in saved["input_columns"]
        if not any(
            column.startswith(f"{text_column}_")
            for text_column in text_columns
        )
    ]

    required_columns = numeric_columns + text_columns
    missing_columns = [
        column for column in required_columns
        if column not in connections.columns
    ]

    if missing_columns:
        st.error(f"Missing required columns: {', '.join(missing_columns)}")
        st.stop()

    st.success("All required connection clues are present.")

    # Use only clues; never use label or attack_cat as input
    clues = connections[required_columns].copy()

    encoded_clues = pd.get_dummies(
        clues,
        columns=text_columns,
        dtype="int8"
    )
    encoded_clues = encoded_clues.reindex(
        columns=saved["input_columns"],
        fill_value=0
    )

    attack_scores = saved["model"].predict_proba(encoded_clues)[:, 1]
    threshold = saved.get("warning_threshold", 0.5)
    flagged = attack_scores >= threshold

    st.metric("Connections needing review", f"{flagged.sum():,}")
    st.caption(f"Warning threshold: {threshold}")

    # Show the connections the model flagged
    # Keep known answers out of the analyst's review table
    results = connections.drop(
        columns=["label", "attack_cat"],
        errors="ignore"
    ).copy()
    results["model_score"] = attack_scores.round(3)
    results["needs_review"] = flagged

    # Prioritize stronger warnings without hiding the others
    results["review_priority"] = "No warning"
    results.loc[flagged, "review_priority"] = "Review"
    results.loc[attack_scores >= 0.7, "review_priority"] = "Higher priority"

    higher_count = (attack_scores >= 0.7).sum()
    other_count = ((attack_scores >= threshold) & (attack_scores < 0.7)).sum()

    st.write(
        f"**Higher priority:** {higher_count:,}  |  "
        f"**Other warnings:** {other_count:,}"
    )

    review_table = results.loc[results["needs_review"]].sort_values(
        "model_score", ascending=False
    )

    st.subheader("Connections to review")
    st.caption(
        "A high model score helps prioritize review. "
        "It does not prove a connection is an attack."
    )
    st.dataframe(review_table.head(100), use_container_width=True)

    # Export every flagged connection, not just the 100 shown on screen
    st.download_button(
        label="Download connections to review",
        data=review_table.to_csv(index=False).encode("utf-8"),
        file_name="connections_to_review.csv",
        mime="text/csv"
    )

    # Evaluate only when the uploaded file includes known answers
    if "label" in connections.columns:
        from sklearn.metrics import confusion_matrix

        actual = connections["label"]
        tn, fp, fn, tp = confusion_matrix(
            actual,
            flagged.astype(int),
            labels=[0, 1]
        ).ravel()

        with st.expander("Model evaluation — labeled data only"):
            st.write(f"Attacks caught: **{tp:,}**")
            st.write(f"Attacks missed: **{fn:,}**")
            st.write(f"False alarms: **{fp:,}**")
            st.write(f"Normal connections left alone: **{tn:,}**")
    # Compare warning rates across protocols
    protocol_summary = (
        results.groupby("proto")["needs_review"]
        .agg(connections="size", warnings="sum")
    )

    protocol_summary = protocol_summary[
        protocol_summary["connections"] >= 50
    ].copy()

    protocol_summary["warning_rate"] = (
        100 * protocol_summary["warnings"] / protocol_summary["connections"]
    )

    st.subheader("Warning rate by protocol")
    st.caption("Only protocols with at least 50 uploaded connections are shown.")
    st.bar_chart(
        protocol_summary["warning_rate"].sort_values(ascending=False).head(10)
    )