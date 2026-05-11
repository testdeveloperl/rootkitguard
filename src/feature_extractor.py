import pandas as pd
import numpy as np
from pathlib import Path

def load_dataset(path: str) -> pd.DataFrame:
    p = Path(path)
    if p.suffix == '.parquet':
        return pd.read_parquet(p)
    return pd.read_csv(p)

def extract_frequency_features(df: pd.DataFrame) -> pd.DataFrame:
    freq = df.pivot_table(
        index='ProcessId', columns='EventID',
        values='UtcTime', aggfunc='count', fill_value=0)
    freq.columns = [f'event_{int(c)}' for c in freq.columns]
    return freq.reset_index()

def extract_process_tree_features(df: pd.DataFrame) -> pd.DataFrame:
    proc = df[df['EventID'] == 1].copy()
    features = proc.groupby('ProcessId').agg(
        process_name   = ('Image', 'first'),
        parent_name    = ('ParentImage', 'first'),
        unique_parents = ('ParentImage', 'nunique'),
        child_count    = ('ProcessId', 'count'),
        cmd_length     = ('CommandLine', lambda x: x.str.len().mean()),
    ).reset_index()
    suspicious_parents = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
    features['suspicious_parent'] = features['parent_name'].str.lower().isin(suspicious_parents).astype(int)
    return features

def extract_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['UtcTime'] = pd.to_datetime(df['UtcTime'])
    df = df.sort_values('UtcTime')
    temporal = df.groupby('ProcessId').agg(
        event_count   = ('EventID', 'count'),
        duration_sec  = ('UtcTime', lambda x: (x.max() - x.min()).total_seconds()),
        unique_events = ('EventID', 'nunique'),
    ).reset_index()
    temporal['events_per_sec'] = (
        temporal['event_count'] / temporal['duration_sec'].replace(0, 1))
    return temporal

def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    freq     = extract_frequency_features(df)
    tree     = extract_process_tree_features(df)
    temporal = extract_temporal_features(df)
    features = freq.merge(tree, on='ProcessId', how='outer')
    features = features.merge(temporal, on='ProcessId', how='outer')
    features = features.fillna(0)
    return features
