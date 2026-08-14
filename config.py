import os
from dotenv import load_dotenv
# from datasets import load_from_disk

load_dotenv()

class Config:
    AI_API_KEY = os.getenv("AI_API_KEY")
    AI_BASE_URL = os.getenv("AI_BASE_URL", "https://api.freetheai.xyz/v1")
    AI_MODEL = os.getenv("AI_MODEL", "min/minimax-m3")
    
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
