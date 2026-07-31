import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # OpenAI API Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    # Supported Languages
    SUPPORTED_LANGUAGES = ["python", "c"]
    
    # CVE Patterns (simplified for demonstration)
    CVE_PATTERNS = {
        "C": [
            {"cve": "CVE-2021-3156", "cwe": "CWE-787", "name": "Heap Buffer Overflow in Sudo"},
            {"cve": "CVE-2017-7529", "cwe": "CWE-190", "name": "Integer Overflow in Nginx"},
        ],
        "Python": [
            {"cve": "CVE-2021-25239", "cwe": "CWE-94", "name": "SSTI in Flask/Jinja2"},
            {"cve": "CVE-2022-22817", "cwe": "CWE-502", "name": "Unsafe Deserialization in PyYAML"},
        ]
    }
    
    # Output directory
    OUTPUT_DIR = "output/reports"