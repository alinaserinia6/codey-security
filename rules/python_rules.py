from typing import List, Dict

PYTHON_RULES = [
    {
        "cve": "CVE-2021-25239",
        "cwe": "CWE-94",
        "name": "Server-Side Template Injection (SSTI)",
        "description": "User input is passed directly to render_template_string, allowing template injection.",
        "patterns": ["render_template_string"],
        "severity": "CRITICAL",
        "sink": "render_template_string",
        "sanitizers": ["escape", "markupsafe.escape"]
    },
    {
        "cve": "CVE-2022-22817",
        "cwe": "CWE-502",
        "name": "Unsafe YAML Deserialization",
        "description": "Using yaml.load() or yaml.unsafe_load() with untrusted input allows arbitrary code execution.",
        "patterns": ["yaml.load", "yaml.unsafe_load"],
        "severity": "CRITICAL",
        "sink": "yaml.load",
        "sanitizers": ["yaml.safe_load"]
    },
    {
        "cve": "CVE-2020-12345",  # Example
        "cwe": "CWE-95",
        "name": "Dynamic Code Execution",
        "description": "Using eval() or exec() with user-controlled input allows arbitrary code execution.",
        "patterns": ["eval(", "exec("],
        "severity": "HIGH",
        "sink": "eval",
        "sanitizers": ["ast.literal_eval"]
    }
]

def get_python_rules() -> List[Dict]:
    return PYTHON_RULES