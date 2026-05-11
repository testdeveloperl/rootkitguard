"""
train_models.py — обучение на поведенческих данных процессов (Sysmon/custom).
Использует feature_extractor.py для построения матрицы признаков.

Запуск:
  python3 src/train_models.py
  python3 src/train_models.py --data data/processed/sysmon_features.csv
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import argparse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import xgboost as xgb
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path

from feature_extractor import build_feature_matrix
from preprocessor import normalize_features, add_isolation_forest_score
from logger import get_logger

log = get_logger("train_models")


# ── Обучение моделей ───────────────────────────────────────────

def train_random_forest(X, y):
    model = RandomForestClassifier(
        n_estimators=100, max_depth=10,
        class_weight='balanced', random_state=42, n_jobs=-1)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=cv, scoring='f1')
    log.info(f"Random Forest F1 (CV): {scores.mean():.3f} ± {scores.std():.3f}")
    print(f"  Random Forest F1 (5-fold CV): {scores.mean():.3f} ± {scores.std():.3f}")
    model.fit(X, y)
    return model


def train_xgboost(X, y):
    scale = (y == 0).sum() / max((y == 1).sum(), 1)
    model = xgb.XGBClassifier(
        n_estimators=100, max_depth=6,
        scale_pos_weight=scale, random_state=42,
        eval_metric='logloss', verbosity=0, n_jobs=-1)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=cv, scoring='f1')
    log.info(f"XGBoost F1 (CV): {scores.mean():.3f} ± {scores.std():.3f}")
    print(f"  XGBoost F1 (5-fold CV):       {scores.mean():.3f} ± {scores.std():.3f}")
    model.fit(X, y)
    return model


def ensemble_predict(rf_model, xgb_model, iso_model, X, num_cols):
    rf_pred  = rf_model.predict(X)
    xgb_pred = xgb_model.predict(X)
    iso_pred = (iso_model.predict(X[num_cols]) == -1).astype(int)
    votes = rf_pred + xgb_pred + iso_pred
    return (votes >= 2).astype(int)


def evaluate(y_true, y_pred, name: str):
    print(f"\n{'='*45}")
    print(f"  Модель: {name}")
    print('='*45)
    print(classification_report(y_true, y_pred, target_names=['Normal', 'Rootkit']))
    auc = roc_auc_score(y_true, y_pred)
    cm  = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  ROC-AUC:             {auc:.4f}")
    print(f"  False Positive Rate: {fp/(fp+tn):.4f}")
    print(f"  False Negative Rate: {fn/(fn+tp):.4f}")
    log.info(f"{name}: AUC={auc:.4f}")


def plot_importance(model, feature_names, out: str):
    imp = pd.DataFrame({'feature': feature_names,
                        'importance': model.feature_importances_}
                       ).sort_values('importance', ascending=True).tail(15)
    plt.figure(figsize=(9, 6))
    plt.barh(imp['feature'], imp['importance'], color='#2d6a4f')
    plt.xlabel('Importance')
    plt.title('Топ-15 признаков (поведенческая модель)')
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    log.info(f"График сохранён: {out}")


# ── Синтетический датасет для тестирования ────────────────────

def make_synthetic_data() -> pd.DataFrame:
    log.info("Синтетический датасет (реальный: положи в data/processed/)")
    return pd.DataFrame({
        'EventID':    [1,1,10,8,1,10,10,1,8,8,1,1,1,1,1],
        'ProcessId':  [100,200,100,100,300,200,300,400,400,400,500,600,700,800,900],
        'Image':      ['cmd.exe','powershell.exe','cmd.exe','cmd.exe','svchost.exe',
                       'powershell.exe','svchost.exe','mimikatz.exe','mimikatz.exe',
                       'mimikatz.exe','explorer.exe','notepad.exe','calc.exe',
                       'chrome.exe','word.exe'],
        'ParentImage':['explorer.exe','winword.exe','explorer.exe','explorer.exe',
                       'services.exe','winword.exe','services.exe','powershell.exe',
                       'powershell.exe','powershell.exe','winlogon.exe','explorer.exe',
                       'explorer.exe','explorer.exe','explorer.exe'],
        'CommandLine':['cmd /c whoami','IEX(New-Object Net.WebClient)','cmd /c whoami',
                       'cmd /c net user','svchost -k','IEX(New-Object Net.WebClient)',
                       'svchost -k','mimikatz privilege::debug',
                       'mimikatz sekurlsa::logonpasswords','mimikatz exit',
                       'explorer.exe','notepad test.txt','calc','chrome','winword'],
        'UtcTime':    pd.date_range('2024-01-01', periods=15, freq='2s'),
        'label':      [0,1,0,1,0,1,0,1,1,1,0,0,0,0,0],
    })


def main(data_path: str = None):
    Path('models').mkdir(exist_ok=True)
    Path('reports').mkdir(exist_ok=True)

    # ── Загрузка данных ───────────────────────────────────
    if data_path and Path(data_path).exists():
        log.info(f"Загружаем: {data_path}")
        raw = pd.read_csv(data_path)
    else:
        log.warning("Файл не найден, используем синтетические данные")
        raw = make_synthetic_data()

    # ── Feature Engineering ───────────────────────────────
    log.info("Построение матрицы признаков...")
    features = build_feature_matrix(raw)

    # Подтянуть метки по ProcessId
    if 'label' in raw.columns:
        labels = raw.groupby('ProcessId')['label'].max().reset_index()
        features = features.merge(labels, on='ProcessId', how='left')
    else:
        features['label'] = 0

    exclude  = ['ProcessId', 'process_name', 'parent_name', 'label']
    num_cols = [c for c in features.columns if c not in exclude]

    X = features[num_cols].fillna(0)
    y = features['label'].fillna(0).astype(int)

    log.info(f"Признаков: {len(num_cols)}, Образцов: {len(X)}, "
             f"Аномалий: {y.sum()}/{len(y)}")

    # ── Нормализация ──────────────────────────────────────
    X_norm, scaler = normalize_features(X.copy())
    X_norm = X_norm[num_cols]

    # ── Обучение ──────────────────────────────────────────
    print("\nОбучаем модели...\n")
    rf_model  = train_random_forest(X_norm, y)
    xgb_model = train_xgboost(X_norm, y)
    _, iso_model = add_isolation_forest_score(X_norm.copy(), num_cols)

    # ── Оценка ───────────────────────────────────────────
    y_pred = ensemble_predict(rf_model, xgb_model, iso_model, X_norm, num_cols)
    evaluate(y, y_pred, "Ensemble (RF + XGBoost + IsoForest)")

    # ── Графики ──────────────────────────────────────────
    plot_importance(rf_model, num_cols, 'reports/behavioral_importance.png')

    # ── Сохранение ───────────────────────────────────────
    joblib.dump(rf_model,  'models/rf_behavioral.pkl')
    joblib.dump(xgb_model, 'models/xgb_behavioral.pkl')
    joblib.dump(scaler,    'models/scaler_behavioral.pkl')
    log.info("Поведенческие модели сохранены в models/")
    print("\n[✓] Модели сохранены в models/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Обучение на поведенческих данных")
    parser.add_argument('--data', default=None,
                        help='Путь к CSV (data/processed/sysmon_features.csv)')
    args = parser.parse_args()
    main(args.data)
