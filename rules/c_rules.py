from typing import List, Dict

C_RULES = [
    {
        "cve": "CVE-2021-3156",
        "cwe": "CWE-787",
        "name": "Heap Buffer Overflow",
        "description": "Unsafe memory operations can lead to heap buffer overflow.",
        "patterns": ["strcpy", "strcat", "sprintf", "gets"],
        "severity": "CRITICAL",
        "sink": "strcpy",
        "sanitizers": ["strncpy", "snprintf", "strlcpy"]
    },
    {
        "cve": "CVE-2017-7529",
        "cwe": "CWE-190",
        "name": "Integer Overflow",
        "description": "Integer overflow in range processing can lead to information disclosure.",
        "patterns": ["range", "content_range"],
        "severity": "HIGH",
        "sink": "range",
        "sanitizers": ["check_overflow"]
    },
    {
        "cve": "CVE-2020-12346",  # Example
        "cwe": "CWE-78",
        "name": "Command Injection",
        "description": "Using system() with user input allows command injection.",
        "patterns": ["system("],
        "severity": "CRITICAL",
        "sink": "system",
        "sanitizers": ["execve", "execvp"]
    }
]

def get_c_rules() -> List[Dict]:
    return C_RULES