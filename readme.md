# Phishing URL Detection

This project aims to build a machine learning model to detect phishing URLs using various features extracted from the URLs themselves and their associated web page characteristics.

## Dataset

We are using the **PhiUSIIL Phishing URL Dataset** provided by `kaggleprollc`. A big thank you to `kaggleprollc` for making this valuable dataset available!

## Work Done So Far

1.  **Data Loading and Initial Inspection**: The dataset was loaded into a pandas DataFrame and its initial shape and column names were inspected.
2.  **Data Cleaning**: 
    *   Duplicate rows were removed from the initial DataFrame.
    *   Irrelevant columns such as `FILENAME`, `URL`, `Domain`, and `Title` were dropped as they are not suitable for direct model training or were too high cardinality.
    *   After dropping these columns, further duplicate rows were identified and removed to ensure uniqueness based on the remaining features.
3.  **Feature Engineering**: A new categorical feature `TLD_risk` was created from the `TLD` (Top-Level Domain) column, categorizing TLDs into different trust levels (High, Medium, Low, Very Low, Unknown). The original `TLD` column was then dropped.
4.  **Data Splitting**: The dataset was split into training and testing sets with a 80/20 ratio, respectively, using `random_state=42` for reproducibility.
5.  **Model Training**: 
    *   A `ColumnTransformer` was used to apply `StandardScaler` to all numerical features. This is crucial for models like Logistic Regression.
    *   A `Pipeline` was constructed, first applying the preprocessing steps and then fitting a `LogisticRegression` model.
    *   The pipeline was trained on the `x_train` and `y_train` data.

## Model Performance Metrics

After training, the Logistic Regression model achieved excellent performance:

### Classification Report (on Test Set):
```
              precision    recall  f1-score       support

0              0.999652  1.000000  0.999826  20123.000000
1              1.000000  0.999740  0.999870  26875.000000

accuracy       0.999851  0.999851  0.999851      0.999851
macro avg      0.999826  0.999870  0.999848  46998.000000
weighted avg   0.999851  0.999851  0.999851  46998.000000
```

### Accuracy Scores:
*   **Train Accuracy**: 0.999904
*   **Test Accuracy**: 0.999851

### Cross-Validation Scores:
Using 10-fold cross-validation, the model consistently performed well:
```
[0.99982978 0.99982978 0.99978722 0.99995744 0.99987233 0.99995744
 0.99991489 0.99974466 0.99995744 0.99982977]
```

*   **Mean Cross-Validation Score**: 0.999868

## Model Persistence

The trained machine learning pipeline (including preprocessing steps and the Logistic Regression model) has been saved to a file named `Phish_guard_model.pkl` using Python's `pickle` module. This allows for easy deployment and reuse of the trained model without needing to retrain it.