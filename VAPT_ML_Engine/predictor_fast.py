import os
import argparse
import joblib
from pathlib import Path

class FastVAPTPredictor:
    def __init__(self, model_path="./models/vapt_rf_model.pkl", vec_path="./models/vapt_rf_vectorizer.pkl"):
        if not os.path.exists(model_path) or not os.path.exists(vec_path):
            raise FileNotFoundError(f"Model or vectorizer not found. Please run train_fast.py first.")
        
        print(f"🤖 Loading Fast ML Model from {model_path}...")
        self.clf = joblib.load(model_path)
        self.vectorizer = joblib.load(vec_path)
        
    def scan_code(self, source_code: str):
        """Scans a piece of source code and returns the vulnerability probability."""
        if not source_code.strip():
            return 0.0
            
        # Fast ML Vectorization
        vec = self.vectorizer.transform([source_code])
        
        # Predict probability for class 1 (Vulnerable)
        probs = self.clf.predict_proba(vec)
        vuln_prob = probs[0][1]
                    
        return vuln_prob

    def scan_file(self, filepath: str):
        """Reads a file and predicts if it is vulnerable."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return self.scan_code(content)
        except Exception as e:
            print(f"⚠️ Error reading {filepath}: {e}")
            return -1.0

    def scan_directory(self, dir_path: str):
        """Scans an entire directory for source files."""
        results = []
        extensions = {'.py', '.c', '.cpp', '.js', '.ts', '.java', '.go', '.php'}
        
        print(f"📂 Scanning directory: {dir_path}")
        for root, _, files in os.walk(dir_path):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    full_path = os.path.join(root, file)
                    prob = self.scan_file(full_path)
                    if prob >= 0:
                        results.append({
                            "file": full_path,
                            "vulnerability_probability": round(prob * 100, 2)
                        })
                        print(f"  ➜ {file}: {round(prob * 100, 2)}% vulnerable")
        
        # Sort by highest probability
        results.sort(key=lambda x: x["vulnerability_probability"], reverse=True)
        return results

def main():
    parser = argparse.ArgumentParser(description="VAPT Fast ML Predictor")
    parser.add_argument("target", type=str, help="File or directory to scan")
    parser.add_argument("--model-path", type=str, default="./models/vapt_rf_model.pkl", help="Path to trained model")
    parser.add_argument("--vec-path", type=str, default="./models/vapt_rf_vectorizer.pkl", help="Path to vectorizer")
    args = parser.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"❌ Target path '{args.target}' does not exist.")
        return

    try:
        predictor = FastVAPTPredictor(model_path=args.model_path, vec_path=args.vec_path)
        
        if target_path.is_file():
            print(f"🔍 Scanning file: {args.target}")
            prob = predictor.scan_file(str(target_path))
            print(f"\n🎯 Result: {round(prob * 100, 2)}% probability of being vulnerable.")
            if prob > 0.5:
                print("🚨 WARNING: High likelihood of vulnerabilities detected!")
            else:
                print("✅ Code appears reasonably safe.")
                
        elif target_path.is_dir():
            results = predictor.scan_directory(str(target_path))
            print("\n📊 --- DIRECTORY SCAN SUMMARY ---")
            for res in results:
                alert = "🚨" if res["vulnerability_probability"] > 50.0 else "✅"
                print(f"{alert} {res['file']}: {res['vulnerability_probability']}%")
                
    except Exception as e:
        print(f"❌ Predictor initialization failed: {e}")

if __name__ == "__main__":
    main()
