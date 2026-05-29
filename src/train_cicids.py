"""
train_cicids.py — обучение моделей на датасете CIC-IDS2018.

Запуск:
  python3 src/train_cicids.py
  python3 src/train_cicids.py --data data/raw/friday_traffic.csv --rows 200000

Сохраняет в models/:
  rf_cicids.pkl, xgb_cicids.pkl, iso_cicids.pkl, scaler_cicids.pkl
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import argparse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import xgboost as xgb
import joblib
import matplotlib
matplotlib.use('Agg')  # без GUI
import matplotlib.pyplot as plt
from pathlib import Path

from logger import get_logger
log = get_logger("train_cicids")


def load_data(path: str, nrows=None) -> pd.DataFrame:
    log.info(f"Загружаем датасет: {path}")
    df = pd.read_csv(path, nrows=nrows)
    log.info(f"Загружено строк: {len(df)}")
    return df


def preprocess(df: pd.DataFrame):
    # Метка: 0 = нормальный, 1 = атака
    if 'Label' not in df.columns:
        raise ValueError("Колонка 'Label' не найдена в датасете")

    df['label'] = (df['Label'] != 'Benign').astype(int)
    df = df.drop(columns=['Label'])
    if 'Timestamp' in df.columns:
        df = df.drop(columns=['Timestamp'])

    # Убрать бесконечности и NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    log.info(f"После очистки: {df.shape}")
    log.info(f"Нормальных: {(df['label']==0).sum():,}")
    log.info(f"Атак:       {(df['label']==1).sum():,}")

    X = df.drop(columns=['label'])
    y = df['label']
    return X, y


def show_results(y_true, y_pred, name: str):
    print(f"\n{'='*50}")
    print(f"  {name}")
    print('='*50)
    print(classification_report(y_true, y_pred, target_names=['Benign', 'Bot']))
    auc = roc_auc_score(y_true, y_pred)
    cm  = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  ROC-AUC:             {auc:.4f}")
    print(f"  False Positive Rate: {fp/(fp+tn):.4f}")
    print(f"  False Negative Rate: {fn/(fn+tp):.4f}")
    log.info(f"{name}: AUC={auc:.4f} FPR={fp/(fp+tn):.4f}")


def plot_feature_importance(model, feature_names, out_path: str):
    importances = pd.DataFrame({
        'feature':    feature_names,
        'importance': model.feature_importances_,
    }).sort_values('importance', ascending=True).tail(20)

    plt.figure(figsize=(10, 8))
    plt.barh(importances['feature'], importances['importance'], color='#378ADD')
    plt.xlabel('Feature Importance')
    plt.title('Топ-20 признаков (Random Forest)')
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close()
    log.info(f"График сохранён: {out_path}")


def main(data_path: str, nrows=None):
    Path('models').mkdir(exist_ok=True)
    Path('reports').mkdir(exist_ok=True)

    # ── 1. Загрузка и предобработка ──────────────────────
    df = load_data(data_path, nrows)
    X, y = preprocess(df)

    # ── 2. Нормализация ───────────────────────────────────
    log.info("Нормализация...")
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

    # ── 3. Разбивка train/test ───────────────────────────
    log.info("Разбивка 80/20 (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y)
    log.info(f"Train: {X_train.shape}, Test: {X_test.shape}")

    # ── 4. Random Forest ─────────────────────────────────
    log.info("Обучение Random Forest (100 деревьев)...")
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=15,
        class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    show_results(y_test, rf_pred, "Random Forest")

    # ── 5. XGBoost ───────────────────────────────────────
    log.info("Обучение XGBoost...")
    scale = (y_train == 0).sum() / (y_train == 1).sum()
    xgb_model = xgb.XGBClassifier(
        n_estimators=100, max_depth=8,
        scale_pos_weight=scale, random_state=42,
        n_jobs=-1, eval_metric='logloss', verbosity=0)
    xgb_model.fit(X_train, y_train)
    xgb_pred = xgb_model.predict(X_test)
    show_results(y_test, xgb_pred, "XGBoost")

    # ── 6. Isolation Forest ──────────────────────────────
    log.info("Обучение Isolation Forest (unsupervised)...")
    contamination = float((y == 1).sum() / len(y))
    contamination = max(0.01, min(contamination, 0.5))
    iso = IsolationForest(
        n_estimators=100, contamination=contamination,
        random_state=42, n_jobs=-1)
    iso.fit(X_train)
    iso_pred = (iso.predict(X_test) == -1).astype(int)
    show_results(y_test, iso_pred, "Isolation Forest")

    # ── 7. Ансамбль ──────────────────────────────────────
    votes         = rf_pred + xgb_pred + iso_pred
    ensemble_pred = (votes >= 2).astype(int)
    show_results(y_test, ensemble_pred, "Ensemble (RF + XGBoost + IsoForest)")

    # ── 8. Feature importance график ─────────────────────
    plot_feature_importance(rf, X.columns, 'reports/feature_importance.png')

    # ── 9. Сохранение ────────────────────────────────────
    joblib.dump(rf,        'models/rf_cicids.pkl')
    joblib.dump(xgb_model, 'models/xgb_cicids.pkl')
    joblib.dump(iso,       'models/iso_cicids.pkl')
    joblib.dump(scaler,    'models/scaler_cicids.pkl')
    log.info("Модели сохранены в models/")
    print("\n[✓] Все модели сохранены в models/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Обучение RootkitGuard на CIC-IDS2018")
    parser.add_argument('--data', default='data/raw/friday_traffic.csv',
                        help='Путь к CSV файлу')
    parser.add_argument('--rows', type=int, default=None,
                        help='Сколько строк читать (None = все)')
    args = parser.parse_args()
    main(args.data, args.rows)
