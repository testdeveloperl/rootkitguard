import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.feature_selection import SelectKBest, f_classif
from pathlib import Path
import joblib

def normalize_features(df: pd.DataFrame, scaler=None):
    exclude = ['ProcessId', 'process_name', 'parent_name', 'label']
    num_cols = [c for c in df.columns if c not in exclude]
    if scaler is None:
        scaler = StandardScaler()
        df[num_cols] = scaler.fit_transform(df[num_cols])
    else:
        df[num_cols] = scaler.transform(df[num_cols])
    return df, scaler

def select_features(X: pd.DataFrame, y: pd.Series, k=10):
    selector = SelectKBest(f_classif, k=min(k, X.shape[1]))
    X_selected = selector.fit_transform(X, y)
    selected_cols = X.columns[selector.get_support()]
    return pd.DataFrame(X_selected, columns=selected_cols), selector

def add_isolation_forest_score(df: pd.DataFrame, num_cols: list):
    iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    df['anomaly_score'] = iso.fit_predict(df[num_cols])
    df['anomaly_raw']   = iso.score_samples(df[num_cols])
    return df, iso

def save_artifacts(scaler, selector, iso, path='models/'):
    Path(path).mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, f'{path}/scaler.pkl')
    if selector: joblib.dump(selector, f'{path}/selector.pkl')
    if iso:      joblib.dump(iso,      f'{path}/isolation_forest.pkl')
    print(f"Artifacts saved in {path}")
