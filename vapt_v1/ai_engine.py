import os
import json
import traceback
from pathlib import Path
from typing import List, Dict, Any, Optional

# --- Offline (Local Llama) ---
try:
    from llama_cpp import Llama
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False
    print("Info: llama_cpp_python not installed. Offline AI mode unavailable.")

# --- Online (Groq API) ---
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    print("Info: httpx not installed. Online AI mode unavailable. Install with: pip install httpx")


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"  # Free tier model on Groq


class AIEngine:
    def __init__(self):
        self.model_path = Path("models") / "Meta-Llama-3-8B-Instruct-Q4_K_M.gguf"
        self.llm = None
        self.groq_api_key: Optional[str] = os.environ.get("GROQ_API_KEY", "")

        # Try loading local model
        if LLAMA_AVAILABLE and self.model_path.exists():
            print(f"Loading local AI Model from {self.model_path}...")
            try:
                self.llm = Llama(
                    model_path=str(self.model_path),
                    n_ctx=4096,
                    n_threads=8,
                    n_gpu_layers=0
                )
                print("Local AI Model loaded successfully.")
            except Exception as e:
                print(f"Failed to load local AI model: {e}")
        else:
            if not LLAMA_AVAILABLE:
                print("Skipping local model (llama_cpp_python not available).")
            elif not self.model_path.exists():
                print(f"Local model not found at {self.model_path}")

    def set_groq_key(self, key: str):
        """Set the Groq API key at runtime."""
        self.groq_api_key = key.strip()

    def is_online_available(self) -> bool:
        """Check if online AI mode is possible."""
        return HTTPX_AVAILABLE and bool(self.groq_api_key)

    def is_offline_available(self) -> bool:
        """Check if offline AI mode is possible."""
        return LLAMA_AVAILABLE and self.llm is not None

    def _build_prompt_messages(self, findings: List[Dict[str, Any]]) -> tuple:
        """Build system + user prompt from findings. Returns (system_msg, user_msg)."""
        system_prompt = (
            "You are an expert cybersecurity analyst and penetration tester. "
            "Review the following vulnerability scanner findings and provide a "
            "comprehensive executive summary report with remediation advice. "
            "Format your response in clean Markdown with headers, bullet points, and tables where appropriate."
        )

        context_str = ""
        for i, finding in enumerate(findings[:25]):
            context_str += f"\nFinding {i+1}: [{finding.get('severity', 'Info')}] {finding.get('vulnerability_name', 'Unknown')}\n"
            desc = finding.get('description', '')
            if desc:
                context_str += f"Description: {desc[:300]}\n"
            fp = finding.get('file_path', '')
            if fp:
                context_str += f"File/Path: {fp}\n"
            ln = finding.get('line_number')
            if ln:
                context_str += f"Line: {ln}\n"

        user_prompt = (
            f"Here are the findings from our security scanners:\n{context_str}\n\n"
            "Please analyze these findings and provide:\n"
            "1. **Executive Summary** — overall risk posture\n"
            "2. **Critical Issues** — top priority vulnerabilities\n"
            "3. **Detailed Analysis** — per-finding breakdown sorted by severity\n"
            "4. **Remediation Steps** — actionable fixes for each issue\n"
            "5. **Risk Score** — overall risk score out of 10\n"
        )

        return system_prompt, user_prompt

    async def analyze_findings_online(self, findings: List[Dict[str, Any]]) -> str:
        """Use Groq API (online) for fast AI analysis."""
        if not HTTPX_AVAILABLE:
            return "### Online AI Unavailable\n\n`httpx` library is not installed. Run `pip install httpx`."

        if not self.groq_api_key:
            return "### Online AI Unavailable\n\nNo Groq API key configured. Set the key in Settings or set the `GROQ_API_KEY` environment variable."

        if not findings:
            return "No vulnerabilities found during the scan."

        system_prompt, user_prompt = self._build_prompt_messages(findings)

        payload = {
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 2048,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.groq_api_key}",
                        "Content-Type": "application/json"
                    },
                    json=payload
                )

                if response.status_code != 200:
                    error_detail = response.text[:500]
                    return f"### Online AI Error\n\nGroq API returned status {response.status_code}:\n```\n{error_detail}\n```"

                data = response.json()
                return data["choices"][0]["message"]["content"].strip()

        except httpx.TimeoutException:
            return "### Online AI Timeout\n\nThe Groq API request timed out. Try again later."
        except Exception as e:
            return f"### Online AI Error\n\n{str(e)}"

    def analyze_findings_offline(self, findings: List[Dict[str, Any]]) -> str:
        """Use local Llama model (offline) for AI analysis."""
        if not LLAMA_AVAILABLE or not self.llm:
            return (
                "### AI Analysis Unavailable\n\n"
                "The local AI model is not loaded. Ensure `llama-cpp-python` is installed "
                "and the model file exists at `models/Meta-Llama-3-8B-Instruct-Q4_K_M.gguf`."
            )

        if not findings:
            return "No vulnerabilities found during the scan."

        system_prompt, user_prompt = self._build_prompt_messages(findings)

        prompt = (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            f"{system_prompt}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n"
            f"{user_prompt}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n"
        )

        print("Starting offline AI analysis...")
        try:
            response = self.llm(
                prompt,
                max_tokens=1024,
                temperature=0.3,
                stop=["<|eot_id|>"]
            )
            return response['choices'][0]['text'].strip()
        except Exception as e:
            return f"### AI Analysis Error\n\n{str(e)}"

    async def analyze_findings(self, findings: List[Dict[str, Any]], ai_mode: str = "offline") -> str:
        """
        Main entry point. Dispatches to online or offline analysis based on ai_mode.
        ai_mode: "online" or "offline"
        """
        if ai_mode == "online" and self.is_online_available():
            return await self.analyze_findings_online(findings)
        elif ai_mode == "offline" and self.is_offline_available():
            return self.analyze_findings_offline(findings)
        elif ai_mode == "online":
            # Online requested but not available — try offline fallback
            if self.is_offline_available():
                return "*(Online AI unavailable, using offline fallback)*\n\n" + self.analyze_findings_offline(findings)
            return "### AI Analysis Unavailable\n\nNeither online nor offline AI is available."
        else:
            # Offline requested but not available
            if self.is_online_available():
                return "*(Offline AI unavailable, using online fallback)*\n\n" + await self.analyze_findings_online(findings)
            return "### AI Analysis Unavailable\n\nNeither online nor offline AI is available."
