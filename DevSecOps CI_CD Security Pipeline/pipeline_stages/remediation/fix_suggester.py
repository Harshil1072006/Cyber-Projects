"""
Fix Suggester.
Provides mapping from CWE and language to specific code fixes.
"""

from typing import Dict, Any, Optional

class FixSuggester:
    """Contains patterns and suggestions for fixing common vulnerabilities."""
    
    SUGGESTIONS = {
        "CWE-89": {
            "python": {
                "title": "Use Parameterized Queries",
                "description": "SQL Injection detected. Do not use f-strings or string concatenation for SQL queries.",
                "example": "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
            },
            "java": {
                "title": "Use PreparedStatement",
                "description": "SQL Injection detected. Use PreparedStatement instead of Statement.",
                "example": "PreparedStatement pstmt = con.prepareStatement(\"SELECT * FROM users WHERE username = ?\"); pstmt.setString(1, username);"
            }
        },
        "CWE-79": {
            "javascript": {
                "title": "Escape HTML Contexts",
                "description": "Cross-Site Scripting (XSS) detected. Ensure user input is properly escaped before rendering in the DOM.",
                "example": "element.textContent = userInput; // Instead of element.innerHTML"
            }
        },
        "CWE-798": {
            "generic": {
                "title": "Remove Hardcoded Secrets",
                "description": "Hardcoded credentials detected. Move this secret to an environment variable or secure vault.",
                "example": "api_key = os.environ.get('API_KEY')"
            }
        }
    }
    
    def get_suggestion(self, cwe: str, language: str) -> Optional[Dict[str, str]]:
        """Retrieves the appropriate suggestion based on CWE and language."""
        if cwe not in self.SUGGESTIONS:
            return None
            
        cwe_fixes = self.SUGGESTIONS[cwe]
        
        # Try specific language first, fallback to generic
        if language in cwe_fixes:
            return cwe_fixes[language]
        elif "generic" in cwe_fixes:
            return cwe_fixes["generic"]
            
        return None
