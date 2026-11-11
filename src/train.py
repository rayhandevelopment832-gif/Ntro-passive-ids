import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
TRAIN_DATA_PATH = BASE_DIR / "data" / "train_features.csv"
TEST_DATA_PATH = BASE_DIR / "data" / "test_features.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "threat_classifier.pkl"

# Configurable decision threshold for attack detection (Range: 0.50 - 0.95)
# Higher values demand higher model confidence to trigger an attack alert,
# defaulting low-confidence predictions back to "benign" to suppress false alarms.
CONFIDENCE_THRESHOLD = 0.85

def apply_threshold_predictions(model, X, threshold=0.85):
    """
    Extracts prediction probabilities and enforces a confidence threshold.
    If the top class probability is below the threshold, the prediction defaults to 'benign'.
    """
    probabilities = model.predict_proba(X)
    classes = model.named_steps["classifier"].classes_
    max_probs = np.max(probabilities, axis=1)
    raw_preds = classes[np.argmax(probabilities, axis=1)]
    
    # Fallback to 'benign' if confidence does not meet the specified threshold
    adjusted_preds = np.where(max_probs >= threshold, raw_preds, "benign")
    return adjusted_preds, max_probs

def main():
    print("\n========== AI PASSIVE IDS: MODEL TRAINING ==========\n")

    # 1. Load datasets
    print("[1/9] Loading synthetic datasets...")
    if not TRAIN_DATA_PATH.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {TRAIN_DATA_PATH}. Run generator first."
        )
    if not TEST_DATA_PATH.exists():
        raise FileNotFoundError(
            f"Testing dataset not found: {TEST_DATA_PATH}. Run generator first."
        )

    train_df = pd.read_csv(TRAIN_DATA_PATH).dropna(subset=["label"])
    test_df = pd.read_csv(TEST_DATA_PATH).dropna(subset=["label"])

    if "label" not in train_df.columns or "label" not in test_df.columns:
        raise ValueError("Both datasets must contain a 'label' column.")

    # 2. Separate features and labels
    print("[2/9] Separating features and labels...")
    X_train = train_df.drop(columns=["label"]).select_dtypes(include=[np.number])
    y_train = train_df["label"].astype(str)

    X_test = test_df.drop(columns=["label"]).select_dtypes(include=[np.number])
    y_test = test_df["label"].astype(str)

    if X_train.empty or X_test.empty:
        raise ValueError("No numerical features found in dataset.")
    if list(X_train.columns) != list(X_test.columns):
        raise ValueError("Feature columns in train and test datasets do not match.")

    feature_columns = X_train.columns.tolist()
    print(f"Training dataset shape: {train_df.shape}")
    print(f"Testing dataset shape: {test_df.shape}")
    print(f"Number of features: {len(feature_columns)}")
    print(f"Number of training classes: {y_train.nunique()}")

    # 3. Print distributions
    print("\n[3/9] Verifying class distributions...")
    print("\nBalanced Training Set Distribution:")
    print(y_train.value_counts())
    print("\nImbalanced Real-World Test Set Distribution:")
    print(y_test.value_counts())
    print(f"\nTotal Training samples: {len(X_train)}")
    print(f"Total Testing samples:  {len(X_test)}")

    # 4. Preprocessing
    print("\n[4/9] Preparing preprocessing pipeline...")
    numeric_preprocessor = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler())
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", numeric_preprocessor, feature_columns)
        ],
        remainder="drop"
    )

    # 5. Random Forest model
    print("\n[5/9] Initializing Random Forest...")
    classifier = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )

    # 6. Complete ML pipeline
    model = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier)
        ]
    )

    # 7. Train on full balanced dataset
    print("\n[6/9] Training model on balanced training set...")
    model.fit(X_train, y_train)
    print("Training completed successfully!")

    # 8. Evaluate model on imbalanced test set with confidence thresholding
    print(f"\n[7/9] Evaluating model on imbalanced test set (Threshold = {CONFIDENCE_THRESHOLD})...")
    predictions, max_probabilities = apply_threshold_predictions(
        model, X_test, threshold=CONFIDENCE_THRESHOLD
    )
    
    accuracy = accuracy_score(y_test, predictions)
    print(f"\nTest Accuracy (Confidence Threshold >= {CONFIDENCE_THRESHOLD}): {accuracy:.4f}")
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    labels = model.named_steps["classifier"].classes_
    cm = confusion_matrix(
        y_test,
        predictions,
        labels=labels
    )
    print("\nConfusion Matrix:")
    print(pd.DataFrame(
        cm,
        index=labels,
        columns=labels
    ))

    # 9. Permutation feature importance on test set
    print("\n[8/9] Calculating permutation feature importance on test set...")
    importance = permutation_importance(
        model,
        X_test,
        y_test,
        n_repeats=5,
        random_state=42,
        scoring="f1_macro",
        n_jobs=-1
    )

    importance_df = pd.DataFrame({
        "feature": feature_columns,
        "importance_mean": importance.importances_mean,
        "importance_std": importance.importances_std
    })
    importance_df = importance_df.sort_values(
        by="importance_mean",
        ascending=False
    )
    print("\nTop 10 Important Features:")
    print(importance_df.head(10).to_string(index=False))

    # Save feature importance report
    importance_df.to_csv(
        TRAIN_DATA_PATH.parent / "feature_importance.csv",
        index=False
    )

    # Save model package including the tuned threshold parameter
    print("\n[9/9] Saving trained model package...")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_package = {
        "model": model,
        "feature_columns": feature_columns,
        "classes": list(labels),
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "training_note": (
            "Trained on 100% balanced synthetic dataset; "
            f"evaluated on independent imbalanced test set with threshold={CONFIDENCE_THRESHOLD}."
        )
    }
    joblib.dump(model_package, MODEL_PATH)

    print("\n========== TRAINING COMPLETED ==========")
    print(f"Model saved: {MODEL_PATH}")
    print(f"Saved Confidence Threshold: {CONFIDENCE_THRESHOLD}")

if __name__ == "__main__":
    main()