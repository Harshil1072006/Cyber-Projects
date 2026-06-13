<div align="center">

# 🧠 VAPT ML Engine

**Machine Learning-Powered Vulnerability Predictor for Source Code**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)]()
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange?style=for-the-badge&logo=scikitlearn)]()
[![Flask](https://img.shields.io/badge/Web_UI-Flask-lightgrey?style=for-the-badge&logo=flask)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📌 What Is VAPT ML Engine?

**VAPT ML Engine** is a machine learning system that predicts whether a given source code snippet contains security vulnerabilities. It uses a **Random Forest classifier** trained on labeled code samples to detect insecure coding patterns — acting as a fast, lightweight alternative to heavier static analysis tools.

It is designed to complement the broader VAPT Platform and can be run as a **CLI predictor**, a **fast variant**, or via a **Flask web interface**.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌲 **Random Forest Model** | High-accuracy ensemble classifier trained on real-world vulnerable code patterns |
| ⚡ **Fast Variant** | Optimized `train_fast.py` and `predictor_fast.py` for quick training and inference |
| 🌐 **Web Interface** | Flask app (`app.py`) for browser-based code analysis |
| 🧪 **Test Samples Included** | Pre-loaded `test_safe.cpp` and `test_vulnerable.cpp` for immediate testing |
| 🛠️ **Modular Design** | Train, predict, and serve independently |

---

## 📁 Project Structure

```
VAPT_ML_Engine/
│
├── train.py                # Full model training script (Random Forest)
├── train_fast.py           # Faster training variant
├── predictor.py            # CLI prediction module — classify a code snippet
├── predictor_fast.py       # Fast CLI predictor variant
├── app.py                  # Flask web interface for interactive analysis
│
├── test_safe.cpp           # Sample safe C++ code (for testing)
├── test_vulnerable.cpp     # Sample vulnerable C++ code (for testing)
│
├── models/                 # Saved trained model files (.pkl)
├── cyber_tools/            # Supporting utility modules
└── static/                 # Flask static assets (CSS, JS)
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install scikit-learn flask joblib
```

### 2. Train the Model
```bash
# Full training
python train.py

# Fast training
python train_fast.py
```

### 3. Predict on a Code Snippet
```bash
# CLI prediction
python predictor.py --file your_code.py

# Fast CLI prediction
python predictor_fast.py --file your_code.py
```

### 4. Launch the Web Interface
```bash
python app.py
# Open http://localhost:5000
```

---

## 🧪 Test It Immediately

```bash
# Test on the included vulnerable C++ sample
python predictor.py --file test_vulnerable.cpp

# Test on the included safe C++ sample
python predictor.py --file test_safe.cpp
```

---

## 🤖 How It Works

1. **Feature Extraction**: Source code is parsed and converted into numerical features (keyword frequency, complexity metrics, dangerous function usage, etc.)
2. **Classification**: A trained Random Forest model classifies the snippet as **Vulnerable** or **Safe** with a confidence score
3. **Output**: The prediction result and confidence level are returned via CLI or the web UI

---

<div align="center">
  <i>Bringing the power of machine learning to proactive vulnerability detection.</i>
</div>
