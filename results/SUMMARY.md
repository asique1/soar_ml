# Pre-defense Results Summary

## What works

- CIC-IDS2017 day CSVs are cleaned with normalized headers, explicit label mapping,
  inf/NaN removal, and duplicate feature-vector removal before any split.
- A reproducible 100,000-row sample trains Logistic Regression, Random Forest, and
  XGBoost on an 80/20 stratified split. The best model is persisted for `/alerts`.
- `/alerts` performs mock enrichment, model scoring, TreeExplainer explanations,
  YAML playbook selection, simulated block/ticket behavior, and timestamps.
- High-risk IP block actions await analyst approval. Telegram delivery is simulated by
  default and real delivery is opt-in. The optional button listener restricts callbacks
  to the configured Telegram chat.
- The three-scenario CIC-backed demo and automated test suite run successfully.

## Evaluation method and measured results

Data: eight CIC-IDS2017 weekday CSVs. The cleaning pipeline retained 2,424,719 rows
and 78 numeric features after dropping invalid rows and duplicate feature vectors.
Evaluation sampled 100,000 rows deterministically and stratified them by benign/attack
label. The random split contains 80,000 training and 20,000 test rows. Metrics are
positive-class (malicious) precision, recall, and F1.

| Split | Model | Precision | Recall | F1 | ROC-AUC | Train-test F1 gap |
|---|---|---:|---:|---:|---:|---:|
| Random 80/20 | Logistic Regression | 0.7301 | 0.9639 | 0.8309 | 0.9878 | 0.0013 |
| Random 80/20 | Random Forest | 0.9972 | 0.9941 | 0.9956 | 0.99994 | 0.0038 |
| Random 80/20 | XGBoost | 0.9984 | 0.9969 | 0.9977 | 0.99998 | 0.0012 |
| Mon-Wed train / Thu-Fri test | Logistic Regression | 0.8508 | 0.6873 | 0.7604 | 0.9026 | 0.1309 |
| Mon-Wed train / Thu-Fri test | Random Forest | 0.9962 | 0.4330 | 0.6036 | 0.9090 | 0.3962 |
| Mon-Wed train / Thu-Fri test | XGBoost | 0.9985 | 0.4318 | 0.6029 | 0.8542 | 0.3971 |

The day-based split uses the same deterministic 100,000-row sample, then partitions
sampled rows by source filename day. It is not a full-data day split.

## Leakage and overfitting checks

- No exact duplicate feature vectors were found across either measured train/test split.
- The largest observed absolute Pearson feature/label correlation was 0.6499
  (`Bwd_Packet_Length_Std`); none reached 0.80.
- These checks do not prove absence of all leakage: Pearson correlation only detects
  linear association, and CIC features can encode dataset-specific acquisition patterns.
- Random-split train/test gaps are small. The large day-split gaps and attack recall
  collapse for both tree models are evidence of substantial temporal distribution shift.
  Treat random-split metrics as optimistic, not as expected production performance.

## Rules-only versus ML triage

The comparison uses the same 20,000 stratified held-out alerts:

- Fixed rule: classify as malicious when destination port is one of
  `21, 22, 23, 3389, 4444, 8080`; all alerts receive an automatic decision.
- ML triage: use probability `0.50` for the label; risk at or above `70` is treated as
  requiring analyst approval and is not counted as automatically handled.
- The saved time values measure local rule evaluation or single-row model inference
  only. They exclude enrichment, endpoint/SQLite/action overhead, external API time,
  and analyst resolution. They are a triage-time proxy, not operational MTTR.

| Strategy | Alerts | Automatically handled | False negatives | Average local triage time / alert |
|---|---:|---:|---:|---:|
| Fixed port rules | 20,000 | 100.00% | 3,136 | 0.000000135 s |
| ML with HITL at risk 70 | 20,000 | 84.00% | 10 | 0.002935 s |

Rules and thresholds are deliberately simple illustrative baselines, not tuned policy.

## Artifacts

- `metrics.csv` — metrics for both splits and all three models
- `confusion_matrix.png` — XGBoost confusion matrix for the random held-out test
- `shap_summary.png` — TreeExplainer summary for a 300-row held-out sample
- `baseline_comparison.csv` — fixed-rule and ML triage comparison
- `evaluation_report.json` — reproducibility details, correlations, metrics, and split sizes
- `demo_output.txt` — full output for true-incident, benign false-positive-alert, and
  borderline scenarios

## Known limitations and risks

1. The thesis metrics use a 100,000-row sample, not the complete cleaned CIC dataset.
2. Temporal generalization is weak for the tree models; external datasets and
   day-based validation should be prioritized.
3. SIEM alerts rarely provide all 78 CIC flow features. The mapper defaults unavailable
   numeric fields to zero, which can distort risk scores; validate input feature coverage
   before operational use.
4. GeoIP remains mock-only. VirusTotal and AbuseIPDB results depend on keys, network
   availability, and provider responses.
5. Real Telegram messages are external side effects when explicitly enabled. Tests and
   the demo use mocked/simulated delivery; no live delivery was used for these results.
6. There is no authentication or role-based access control on API approval endpoints.
   The Telegram callback listener checks only the configured chat ID.
7. Baseline timing is not end-to-end latency and is not a measured MTTR.

## Five suggested next steps

1. Investigate temporal drift with day-specific reports and validate on a separate
   capture or CIC-IDS2018/UNSW-NB15 before presenting production claims.
2. Define and validate a SIEM-to-CIC feature contract; measure missing-feature rates and
   replace unverified zero defaults with documented, training-consistent preprocessing.
3. Select risk thresholds using a validation set and operational false-positive/false-
   negative costs, then lock the test set for final evaluation.
4. Add authentication, analyst authorization, audit access controls, and safer secret
   rotation/management before exposing the API or approval listener.
5. Measure full end-to-end latency and alert resolution times with enrichment, SQLite,
   playbooks, and analyst actions included; report MTTR separately from inference time.
