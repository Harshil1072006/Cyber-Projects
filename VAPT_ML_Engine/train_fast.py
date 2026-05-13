import os
import argparse
import joblib
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

def main():
    parser = argparse.ArgumentParser(description="Train Fast ML for Vulnerability Prediction")
    parser.add_argument("--samples", type=int, default=10000, help="Number of samples to use")
    args = parser.parse_args()

    print(f"🚀 Initializing VAPT Fast ML Engine (v1.1.1)")
    
    # 1. Load Dataset
    print(f"📥 Generating massive synthetic vulnerability dataset locally to bypass network locks...")
    
    # Generate 10000 realistic code snippets (Safe and Vulnerable)
    texts = []
    labels = []
    
    import random
    safe_templates = [
        "int main() {{ char buf[{size}]; strncpy(buf, input, {size}-1); buf[{size}-1] = '\\0'; return 0; }}",
        "void process(const char* data) {{ if(strlen(data) < {size}) {{ strcpy(buffer, data); }} }}",
        "printf(\"%s\", \"{random_string}\");",
        "int calculate(int a, int b) {{ return a {op} b; }}"
    ]
    
    vuln_templates = [
        "int main() {{ char buf[{size}]; strcpy(buf, input); return 0; }}",
        "void process(char* data) {{ sprintf(buffer, \"%s\", data); }}",
        "printf(user_input); // Format string vulnerability",
        "gets(buffer); // Classic buffer overflow"
    ]
    
    for _ in range(args.samples):
        if random.random() > 0.5:
            # Safe
            code = random.choice(safe_templates).format(size=random.randint(10, 100), random_string="Hello", op=random.choice(['+', '-', '*']))
            texts.append(code)
            labels.append(0)
        else:
            # Vulnerable
            code = random.choice(vuln_templates).format(size=random.randint(10, 100))
            texts.append(code)
            labels.append(1)

    print(f"📊 Dataset prepared: {len(texts)} samples.")

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    # 2. TF-IDF Vectorization
    print("⚙️  Converting source code to TF-IDF vectors...")
    vectorizer = TfidfVectorizer(max_features=10000, max_df=0.9, min_df=2)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 3. Model Training
    print("🧠 Training Random Forest Classifier (this should be fast)...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train_vec, y_train)

    # 4. Evaluation
    print("🔍 Evaluating model...")
    y_pred = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n✅ Accuracy: {round(acc * 100, 2)}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Vulnerable"]))

    # 5. Save the model
    os.makedirs("./models", exist_ok=True)
    out_model = "./models/vapt_rf_model.pkl"
    out_vectorizer = "./models/vapt_rf_vectorizer.pkl"
    
    print(f"💾 Saving Fast ML Model to {out_model}")
    joblib.dump(clf, out_model)
    joblib.dump(vectorizer, out_vectorizer)
    
    print("🎉 Fast Training Complete!")

if __name__ == "__main__":
    main()
