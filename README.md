## Project 21: Network Traffic Anomaly Detection
A machine learning dashboard that analyzes recorded network connections and highlights suspicious traffic for human review.

User can try a built-in demo or upload their own supported network records. The dashboard displays model warningsm traffic observations and evaluation results when known labels are available.

Built with Python, Streamlit, Pandas and scikit-learn.

## Features

- **Built-in demo:** Explore sample Zeek traffic without uploading a file.
- **File upload:** Analyze UNSW-NB15 CSV files or supported Zeek connection logs.
- **Colour-coded dashboard:** View warnings in red, unflagged connections
  in green, false alarms in orange, and missed attacks in purple.
  False alarms and missed attacks require known labels.
- **Traffic observations:** Inspect recorded patterns, including missing
  replies, rejected connections, and repeated connections to the same
  destination within two minutes.
- **Connection details:** Filter results and inspect individual connections.
- **Model evaluation:** View detection counts, false-alarm rate, and attack
  recall when complete supported labels are available.
- **Download results:** Export the selected connection view as a CSV file.


## How It Works

1. Choose the built-in demo or upload a supported network log.
2. The app prepares the connection features and applies the
   saved model for the selected format.
3. Connections with a model score at or above the warning
   threshold are flagged for review.
4. The dashboard shows the results and measured traffic
   observations for inspection.

Traffic observations describe patterns found in the records.
They do not explain the model's exact reasoning.

When complete supported labels are available, the app also
identifies false alarms and missed attacks, and calculates
evaluation metrics.

The app analyzes recorded traffic; it does not monitor
live network activity.

## Demo Evaluation Results

On the bundled Zeek sample (`capture_8_1.log`), the app
analyzed 10,403 connections.

| Result | Value |
|---|---:|
| Malicious connections caught | 8,218 |
| Malicious connections missed | 4 |
| False alarms | 2 |
| Normal connections left alone | 2,179 |
| False-alarm rate | 0.092% |
| Attack recall | 99.95% |

These results compare model predictions with the sample's
known labels at a warning threshold of 0.5.

They describe performance on this capture and do not
guarantee the same performance on other network traffic.


## Datasets

This project uses two network traffic formats:

### UNSW-NB15

- **Training set:** Used to train the UNSW-NB15 detection model.
- **Test set:** Used to evaluate the trained model on separate data.
- Includes connection features and labels identifying normal
  and attack traffic.

### Zeek Connection Logs

The project also uses Zeek connection logs from IoT-23
for the Zeek detection workflow.

These records include timestamps, source and destination
addresses, protocols, packet counts, and connection states.

The built-in demo uses `capture_8_1.log`, which includes
benign and malicious labels for evaluation.

Separate saved models handle UNSW-NB15 data and Zeek logs.

## Limitations

- This is a portfolio prototype for analyzing recorded traffic.
  It does not collect live traffic or block attacks.
- A warning requires human review; it is not a confirmed attack.
  An unflagged connection is not guaranteed safe.
- Model scores are not calibrated real-world attack probabilities.
- Traffic observations describe measured patterns, not the
  model's exact reasoning.
- False alarms and missed attacks can only be identified
  when complete supported labels are available.
- Performance on the demo capture may not represent
  performance on other devices or networks.
- Uploaded files must contain the features required by
  the selected model.


## Notes
### The meaining of the columns
dur - How long the connection lasted, in seconds

proto - The communication method, or protocol

spkts - Number of data packets sent by the source computer

dpkts - Numbers of packets sent back by the destination computer

attack_cat - The type assigned by the dataset researchers

label - 0 = normal, 1 = attack 


## NB1 :
Can We spot attacks by looking at information about computer connections?
1. We looked at the dataset. Each row is one connection; label tells us whether it was normal (0) or an attack (1).
2. We tried a simple rule: flag connections with no reply. It caught some attacks but missed many.
3. We tried two models. Random Forest caught far more attacks than Isolation Forest.
4. We checked its mistakes. On the official test set, our selected Random Forest caught about 99% of attacks, but also flagged 11,544 normal connections.
5. We investigated those false alarms and found many involved normal FIN connections. Removing one heavily used clue did not fix the problem.
In one sentence: we built an attack detector, measured how well it worked, and found that its many false alarms are the main problem to explain in our project.
( iT CATCHES ATTACKS BUT ALSO MANY False alarms)

## Zeek records clues

| Field | Simple meaning |
|---|---|
| `duration` | How long the connection lasted |
| `proto` | Protocol, such as TCP |
| `orig_pkts` | Packets sent by the side that started the connection |
| `resp_pkts` | Packets sent back |
| `orig_bytes` | Payload bytes sent |
| `resp_bytes` | Payload bytes returned |
