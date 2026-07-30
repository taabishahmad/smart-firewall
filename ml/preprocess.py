"""
NSL-KDD preprocessing utilities shared by the training pipeline and the live
detection engine. Keeping the column definitions and encoders in one place is
what stops training-serving skew: the classifier sees features in the exact
same order and encoding whether it is being trained offline or scoring a live
flow captured off the wire.
"""

import numpy as np
import pandas as pd

# The 41 NSL-KDD features + the label + the per-record difficulty score that
# ships in the "+"" variants of the dataset.
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

# Content features (hot, num_failed_logins, num_compromised, ...) are omitted on
# purpose. They can only be derived from packet payloads / application-layer
# state, which a lightweight real-time firewall cannot reconstruct without deep
# packet inspection. We keep the basic connection features, the two-second
# time-based traffic features, and the 100-connection host-based features, all
# of which a flow aggregator can compute from packet headers alone.
FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL = ["protocol_type", "service", "flag"]
NUMERIC = [c for c in FEATURES if c not in CATEGORICAL]

# Anything that is not "normal" in NSL-KDD is an attack. The dataset labels the
# specific attack family (neptune, satan, smurf, ...); we collapse those to a
# single malicious class because the firewall only needs a block / allow verdict.
def to_binary_label(series: pd.Series) -> pd.Series:
    return (series.str.strip().str.lower() != "normal").astype(int)


class CategoryEncoder:
    """
    Minimal ordinal encoder that remembers the categories it saw during fit and
    maps anything unseen at inference time to a reserved code. sklearn's own
    encoders raise on unknown categories, which is no good for live traffic that
    can carry a service or TCP flag combination the training set never contained.
    """

    def __init__(self):
        self.mapping = {}

    def fit(self, df: pd.DataFrame):
        for col in CATEGORICAL:
            cats = sorted(df[col].astype(str).str.strip().unique())
            # code 0 is reserved for "unseen"; real categories start at 1
            self.mapping[col] = {c: i + 1 for i, c in enumerate(cats)}
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = df.copy()
        for col in CATEGORICAL:
            table = self.mapping[col]
            out[col] = (
                out[col].astype(str).str.strip().map(table).fillna(0).astype(int)
            )
        return out

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        return self.fit(df).transform(df)


def load_raw(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
    return df


def build_xy(df: pd.DataFrame, encoder: CategoryEncoder = None, fit: bool = False):
    """Return (X, y, encoder) with the selected feature columns encoded."""
    y = to_binary_label(df["label"])
    x = df[FEATURES].copy()
    if fit:
        encoder = CategoryEncoder().fit(x)
    x = encoder.transform(x)
    x = x[FEATURES].astype(float)
    return x, y, encoder
