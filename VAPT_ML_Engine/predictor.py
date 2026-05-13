import os
import argparse
import ast
import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification

class VAPTPredictor:
    def __init__(self, model_dir="./models/vapt_nn_final"):
        self.model_dir = model_dir
        if not os.path.exists(model_dir):
            raise FileNotFoundError(f"Model directory '{model_dir}' not found. Please run train.py first.")
        
        print(f"🤖 Loading Neural Network from {model_dir}...")
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(self.device)
        self.model.eval()
        
    def _chunk_text(self, text, chunk_size=500):
        # Extremely basic chunking: CodeBERT has a strict 512 token limit.
        words = text.split()
        return [" ".join(words[i:i + chunk_size]) for i in range(0, len(words), chunk_size)]

    def scan_code(self, source_code: str):
        """Scans a piece of source code and returns the vulnerability probability."""
        if not source_code.strip():
            return 0.0
            
        chunks = self._chunk_text(source_code)
        max_prob = 0.0
        
        with torch.no_grad():
            for chunk in chunks:
                inputs = self.tokenizer(chunk, return_tensors="pt", truncation=True, max_length=512, padding="max_length")
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                outputs = self.model(**inputs)
                # Softmax to get probabilities
                probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
                
                # Class 1 is 'vulnerable'
                vuln_prob = probs[0][1].item()
                if vuln_prob > max_prob:
                    max_prob = vuln_prob
                    
        return max_prob

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
    parser = argparse.ArgumentParser(description="VAPT ML Engine Predictor")
    parser.add_argument("target", type=str, help="File or directory to scan")
    parser.add_argument("--model-dir", type=str, default="./models/vapt_nn_final", help="Path to trained model")
    args = parser.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"❌ Target path '{args.target}' does not exist.")
        return

    try:
        predictor = VAPTPredictor(model_dir=args.model_dir)
        
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
