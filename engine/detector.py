"""
Loads the trained model bundle and scores feature vectors produced by the
aggregator. The model gives the block / allow verdict and a confidence; a small
rule of thumb over the same features labels the attack family for the operator
(port scan, flood, brute force) so the dashboard can say more than "malicious".
"""

import os

import joblib
import pandas as pd

ARTIFACT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ml", "artifacts", "firewall_model.joblib",
)


class Detector:
    def __init__(self, path=ARTIFACT):
        bundle = joblib.load(path)
        self.model = bundle["model"]
        self.encoder = bundle["encoder"]
        self.features = bundle["features"]
        self.model_name = bundle.get("model_name", "model")
        self.trained_at = bundle.get("trained_at")

    def score(self, feat: dict):
        row = pd.DataFrame([feat])[self.features]
        row = self.encoder.transform(row)[self.features].astype(float)
        pred = int(self.model.predict(row)[0])
        try:
            proba = float(self.model.predict_proba(row)[0][1])
        except Exception:
            proba = float(pred)
        return pred, proba

    @staticmethod
    def classify_attack(feat: dict) -> str:
        """Best-effort attack family from the feature pattern, for display."""
        flag = feat.get("flag")
        count = feat.get("count", 0)
        diff_srv = feat.get("diff_srv_rate", 0)
        same_srv = feat.get("same_srv_rate", 0)
        serror = feat.get("serror_rate", 0)
        rerror = feat.get("rerror_rate", 0)
        dst_bytes = feat.get("dst_bytes", 0)

        # many different services on one host -> reconnaissance scan
        if diff_srv >= 0.5 and count >= 3:
            return "Port scan"
        # rejected / reset attempts against one service -> credential guessing
        if flag in ("REJ", "RSTO", "RSTR") and same_srv >= 0.5 and count >= 3:
            return "Brute force"
        if rerror >= 0.4 and count >= 3:
            return "Brute force"
        # half-open flood against one service
        if flag == "S0" and same_srv >= 0.6 and count >= 3:
            return "DoS / flood"
        if serror >= 0.6 and count >= 6:
            return "DoS / flood"
        if flag in ("S0", "REJ") and count >= 3:
            return "Probe"
        return "Anomalous traffic"
