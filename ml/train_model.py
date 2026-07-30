"""
Train and evaluate the intrusion-detection classifier on NSL-KDD.

Two evaluations are produced on purpose:

  * within-distribution  - a stratified 80/20 split of KDDTrain+. This is the
    number the project targets (>= 90%) and the one most comparable to the
    figures quoted in the IDS literature that split a single dataset.

  * generalisation       - train on the whole of KDDTrain+, score against the
    separate KDDTest+ file. KDDTest+ deliberately contains attack types absent
    from training, so this number is lower and is reported honestly as a measure
    of how the model copes with previously unseen attacks.

The final shipped model is refit on the entire training file and saved together
with its category encoder so the live engine can load a single artefact.
"""

import json
import os
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier

import preprocess as pp

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "ml", "artifacts")
os.makedirs(OUT, exist_ok=True)


def score(name, model, x_test, y_test):
    pred = model.predict(x_test)
    row = {
        "model": name,
        "accuracy": round(accuracy_score(y_test, pred) * 100, 2),
        "precision": round(precision_score(y_test, pred) * 100, 2),
        "recall": round(recall_score(y_test, pred) * 100, 2),
        "f1": round(f1_score(y_test, pred) * 100, 2),
    }
    try:
        proba = model.predict_proba(x_test)[:, 1]
        row["roc_auc"] = round(roc_auc_score(y_test, proba) * 100, 2)
    except Exception:
        row["roc_auc"] = None
    return row, pred


def candidate_models():
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=120, max_depth=None, n_jobs=-1, random_state=42
        ),
        "Decision Tree": DecisionTreeClassifier(max_depth=25, random_state=42),
        "Naive Bayes": GaussianNB(),
    }


def main():
    print("Loading NSL-KDD ...")
    train_df = pp.load_raw(os.path.join(DATA, "KDDTrain+.txt"))
    test_df = pp.load_raw(os.path.join(DATA, "KDDTest+.txt"))
    print(f"  KDDTrain+: {len(train_df):,} rows")
    print(f"  KDDTest+ : {len(test_df):,} rows")

    x_all, y_all, encoder = pp.build_xy(train_df, fit=True)
    x_kddtest, y_kddtest, _ = pp.build_xy(test_df, encoder=encoder)

    # ---- within-distribution comparison -------------------------------------
    x_tr, x_te, y_tr, y_te = train_test_split(
        x_all, y_all, test_size=0.2, stratify=y_all, random_state=42
    )

    within = []
    trained = {}
    print("\nWithin-distribution comparison (80/20 split of KDDTrain+):")
    for name, model in candidate_models().items():
        t0 = time.time()
        model.fit(x_tr, y_tr)
        row, _ = score(name, model, x_te, y_te)
        row["train_seconds"] = round(time.time() - t0, 2)
        within.append(row)
        trained[name] = model
        print(f"  {name:<15} acc={row['accuracy']:>6}%  f1={row['f1']:>6}%")

    best_name = max(within, key=lambda r: r["f1"])["model"]
    print(f"\nBest by F1: {best_name}")

    # ---- generalisation on the held-out KDDTest+ ----------------------------
    generalisation = []
    print("\nGeneralisation (train on KDDTrain+, test on KDDTest+):")
    for name, model in candidate_models().items():
        model.fit(x_all, y_all)
        row, pred = score(name, model, x_kddtest, y_kddtest)
        generalisation.append(row)
        print(f"  {name:<15} acc={row['accuracy']:>6}%  f1={row['f1']:>6}%")
        if name == best_name:
            cm_gen = confusion_matrix(y_kddtest, pred).tolist()

    # ---- fit the shipped model on everything --------------------------------
    final = candidate_models()[best_name]
    final.fit(x_all, y_all)
    within_pred = final.predict(x_te)  # for a representative confusion matrix
    cm_within = confusion_matrix(y_te, within_pred).tolist()

    importances = None
    if hasattr(final, "feature_importances_"):
        importances = sorted(
            [
                {"feature": f, "importance": round(float(v), 4)}
                for f, v in zip(pp.FEATURES, final.feature_importances_)
            ],
            key=lambda r: r["importance"],
            reverse=True,
        )

    bundle = {
        "model": final,
        "encoder": encoder,
        "features": pp.FEATURES,
        "categorical": pp.CATEGORICAL,
        "model_name": best_name,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    joblib.dump(bundle, os.path.join(OUT, "firewall_model.joblib"))

    metrics = {
        "best_model": best_name,
        "trained_at": bundle["trained_at"],
        "dataset": {
            "name": "NSL-KDD",
            "train_rows": len(train_df),
            "test_rows": len(test_df),
            "features_used": len(pp.FEATURES),
            "attack_ratio_train": round(float(y_all.mean()) * 100, 2),
        },
        "within_distribution": within,
        "generalisation": generalisation,
        "confusion_matrix_within": cm_within,
        "confusion_matrix_generalisation": cm_gen,
        "feature_importances": importances,
        "class_labels": ["normal", "malicious"],
    }
    with open(os.path.join(OUT, "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)

    print("\nSaved:")
    print(f"  {os.path.join(OUT, 'firewall_model.joblib')}")
    print(f"  {os.path.join(OUT, 'metrics.json')}")
    print(f"\nShipped model: {best_name}")
    headline = next(r for r in within if r["model"] == best_name)
    print(f"Within-distribution accuracy: {headline['accuracy']}%  "
          f"F1: {headline['f1']}%")


if __name__ == "__main__":
    main()
