# PhishGuard

PhishGuard is a machine learning–powered phishing URL detection system that predicts whether a URL is legitimate or malicious based purely on its structure — without visiting the website.

This repository focuses on the **ML part of the project**: data, feature engineering, model training, threshold tuning, and evaluation.

---

## 🎯 Key Idea

- supervised binary classification: phishing (1) vs legitimate (0)  
- URL-based feature engineering (no page content fetching)  
- probability output with a tuned decision threshold (0.3)  
- evaluation using precision, recall, f1-score, and confusion matrix  

---

## 🧠 Why I Built This

Phishing attacks are one of the most common cybersecurity threats. Many users click suspicious links without realizing the risk.

This project was built to:

- apply machine learning to a real-world security problem  
- understand how feature engineering affects security models  
- practice model selection, calibration, and threshold tuning  
- analyze trade-offs between precision and recall for phishing detection  

---

## 🛠️ ML Stack

- **Language**: Python  
- **Core libraries**: `scikit-learn`, `pandas`, `numpy`  
- **Evaluation**: `classification_report`, `confusion_matrix` from `sklearn.metrics`  
- **Experimentation**: Jupyter/Colab notebooks  

---

## 📊 Model Evaluation

Instead of using the default threshold (0.5), the model uses:

```python
from sklearn.metrics import classification_report, confusion_matrix

y_prob = pipe.predict_proba(X_test)[:, 1]
y_pred = (y_prob > 0.3).astype(int)

print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))
```

This improves phishing detection (recall), which is critical in security systems.

---

### 📈 Classification Metrics

**Per-class performance**

| Class | Description  | Precision | Recall | F1-score | Support |
|-------|--------------|-----------|--------|----------|---------|
| 0     | Legitimate   | 0.99      | 0.96   | 0.97     | 10000   |
| 1     | Phishing     | 0.67      | 0.89   | 0.76     | 1000    |

**Overall performance**

| Metric        | Value |
|--------------|-------|
| Accuracy     | 0.95  |
| Macro Recall | 0.92  |
| Macro F1     | 0.87  |

---

### 🔍 Confusion Matrix

|                        | Predicted Legitimate (0) | Predicted Phishing (1) |
|------------------------|--------------------------|------------------------|
| **True Legitimate (0)** | 9552                     | 448                    |
| **True Phishing (1)**   | 107                      | 893                    |

---

### 🧠 Key Insights

- overall accuracy: **95%**  
- phishing recall: **89%** (very important)  
- phishing precision: **67%**  
- model is tuned to **reduce missed phishing attacks**  

In cybersecurity, missing a phishing URL is worse than flagging a safe one, so recall on the phishing class is prioritized.

---

## 🔧 Features Used

The model uses handcrafted URL-based features such as:

- URL length  
- domain length  
- IP-based domain detection  
- TLD (Top-Level Domain) risk scoring  
- number of subdomains  
- obfuscation detection  
- letter and digit ratios  
- special character counts  
- HTTPS presence  
- suspicious keyword detection  
- hyphen count  

These features try to capture patterns common in phishing URLs, like excessive obfuscation, suspicious keywords, and risky TLDs.

---

## ⚠️ Limitations

- Uses only URL-based features (no webpage content analysis)  
- May struggle with highly sophisticated or very new phishing campaigns  
- Dataset bias can affect generalization to unseen domains  

---

## 🚀 Future ML Improvements

- integrate domain reputation / blacklist scores as additional features  
- improve phishing precision while maintaining high recall  
- add explainability (e.g. feature importance per prediction)  
- explore more advanced models and calibration techniques  

---

## 👨‍💻 Author

Built as a machine learning project focused on phishing detection, feature engineering, and model evaluation.

# 🚀 PhishGuard

PhishGuard is a machine learning–powered phishing URL detection system that predicts whether a URL is legitimate or malicious based purely on its structure — without visiting the website.

It is built as a full-stack ML project, combining:
- 🧠 Machine Learning model  
- ⚡ FastAPI backend  
- 🌐 Streamlit frontend  
- ☁️ Cloud deployment  

---

## 🌐 Live Demo

- 🚀 Frontend: (Add your Streamlit link here)  
- ⚡ API: (Add your Render link here)  

---

## 🎯 Key Features

- 🔍 Detect phishing URLs using ML  
- ⚡ FastAPI backend with API key authentication  
- 📊 Probability-based prediction (not just binary output)  
- 🚨 Risk-level classification (Low / Suspicious / High Risk)  
- 📁 Batch prediction using CSV upload  
- 🌐 Interactive Streamlit UI  
- 🔐 Secure deployment with environment variables  

---

## 🧠 Why I Built This

Phishing attacks are one of the most common cybersecurity threats. Many users click suspicious links without realizing the risk.

This project was built to:

- apply machine learning to a real-world security problem  
- convert a notebook model into a production-ready API  
- build a complete ML system (backend + frontend + deployment)  
- understand real-world challenges like dataset bias and model tuning  

---

## 🛠️ Tech Stack

### Machine Learning
- scikit-learn
- pandas
- custom URL feature engineering
- threshold tuning for phishing detection

### Backend
- FastAPI
- Uvicorn
- python-dotenv

### Frontend
- Streamlit
- requests

### Deployment
- Render (FastAPI backend)
- Streamlit Cloud (frontend)
- GitHub

---

## 📊 Model Evaluation

Instead of using the default threshold (0.5), the model uses:

y_pred = (y_prob > 0.3).astype(int)

This improves phishing detection (recall), which is critical in security systems.

---

### 📈 Classification Report

precision    recall  f1-score   support

0       0.99      0.96      0.97     10000  
1       0.67      0.89      0.76      1000  

accuracy                           0.95     11000  

---

### 🔍 Confusion Matrix

[[9552  448]  
 [ 107  893]]

---

### 🧠 Key Insights

- Accuracy: 95%  
- Phishing Recall: 89% (very important)  
- Phishing Precision: 67%  
- Model tuned to reduce missed phishing attacks  

In cybersecurity, missing a phishing URL is worse than flagging a safe one.

---

## 🔧 Features Used

The model uses handcrafted URL-based features such as:

- URL length  
- domain length  
- IP-based domain detection  
- TLD (Top-Level Domain) risk scoring  
- number of subdomains  
- obfuscation detection  
- letter and digit ratios  
- special character counts  
- HTTPS presence  
- suspicious keyword detection  
- hyphen count  

---

## ⚡ API Usage

### Welcome Route

curl -H "x-api-key: YOUR_KEY" http://127.0.0.1:8000/

---

### Predict URL

curl -X POST "http://127.0.0.1:8000/predict" \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_KEY" \
  -d '{"url":"https://google.com"}'

---

### Example Response

{
  "url": "https://google.com",
  "prediction": "legitimate",
  "risk": "Low Risk",
  "confidence": 0.9934,
  "phishing_probability": 0.0066
}

---

## 💻 Run Locally

### 1. Create virtual environment

python3 -m venv venv  
source venv/bin/activate  
pip install -r requirements.txt  

---

### 2. Configure Environment Variables

Create fastAPI/.env:

API_KEY=your_key_here  
PHISHING_CLASS=1  

---

### 3. Run FastAPI Backend

uvicorn fastAPI.app:app --reload --port 8000  

Docs:  
http://127.0.0.1:8000/docs  

---

### 4. Run Streamlit Frontend

cd frontend  
streamlit run app.py  

Open:  
http://localhost:8501  

---

## ☁️ Deployment

### FastAPI on Render

Build:
pip install -r requirements.txt  

Start:
uvicorn fastAPI.app:app --host 0.0.0.0 --port $PORT  

Environment variables:
API_KEY  
PHISHING_CLASS  

---

### Streamlit on Cloud

Set secrets:

API_BASE_URL="https://your-api-url"  
API_KEY="your_key"  

---

## ⚠️ Limitations

- Uses only URL-based features (no webpage content analysis)  
- May struggle with highly sophisticated phishing URLs  
- Dataset bias can affect generalization  

---

## 🚀 Future Improvements

- integrate domain reputation / blacklist APIs  
- improve phishing precision while maintaining recall  
- add explainability for predictions  
- store prediction logs and analytics  
- extend to webpage content analysis  

---

## 👨‍💻 Author

Built as a full-stack machine learning project focused on phishing detection, model deployment, and real-world usability.

---

## 🔥 Final Note

This project demonstrates:

- Machine Learning  
- Feature Engineering  
- Model Tuning  
- API Development  
- Frontend Integration  
- Deployment  

Not just a model — a complete ML system 🚀# PhishGuard
