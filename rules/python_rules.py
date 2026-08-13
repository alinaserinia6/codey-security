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
        "cve": "N/A",
        "cwe": "CWE-95",
        "name": "Dynamic Code Execution",
        "description": "Using eval() or exec() with user-controlled input allows arbitrary code execution.",
        "patterns": ["eval(", "exec("],
        "severity": "HIGH",
        "sink": "eval",
        "sanitizers": ["ast.literal_eval"]
    },
    {
        "cve": "CVE-2022-29217",
        "cwe": "CWE-89",
        "name": "SQL Injection",
        "description": "String concatenation or format strings used to build SQL queries allow injection.",
        "patterns": ["execute(\"", "execute(f\"", "execute('", "execute(f'", "executemany("],
        "severity": "CRITICAL",
        "sink": "execute",
        "sanitizers": ["parameterized", "?", "execute(sql, params)"]
    },
    {
        "cve": "N/A",
        "cwe": "CWE-78",
        "name": "Command Injection",
        "description": "Using os.system or subprocess with shell=True and user input allows command injection.",
        "patterns": ["os.system(", "os.popen(", "subprocess.call(", "subprocess.Popen(", "shell=True"],
        "severity": "CRITICAL",
        "sink": "os.system",
        "sanitizers": ["shell=False", "shlex.quote", "shlex.split"]
    },
    {
        "cve": "N/A",
        "cwe": "CWE-22",
        "name": "Path Traversal",
        "description": "Joining user-controlled input with file paths allows directory traversal.",
        "patterns": ["os.path.join(", "open(user", "open(request", "open(input"],
        "severity": "HIGH",
        "sink": "open",
        "sanitizers": ["os.path.realpath", "os.path.commonpath", "secure_filename"]
    },
    {
        "cve": "CVE-2020-26160",
        "cwe": "CWE-601",
        "name": "Open Redirect",
        "description": "Redirecting to a user-supplied URL without validation allows phishing attacks.",
        "patterns": ["redirect(request.", "redirect(url, code="],
        "severity": "MEDIUM",
        "sink": "redirect",
        "sanitizers": ["urlparse", "is_safe_url", "allowed_hosts"]
    },
    {
        "cve": "CVE-2019-1010023",
        "cwe": "CWE-327",
        "name": "Weak Cryptographic Hash",
        "description": "Using MD5 or SHA1 for security-sensitive purposes is cryptographically broken.",
        "patterns": ["hashlib.md5(", "hashlib.sha1(", "Crypto.Hash.MD5", "Crypto.Hash.SHA1"],
        "severity": "MEDIUM",
        "sink": "hashlib.md5",
        "sanitizers": ["hashlib.sha256", "hashlib.sha3", "hashlib.blake2"]
    },
    {
        "cve": "CVE-2020-26159",
        "cwe": "CWE-330",
        "name": "Insecure Randomness",
        "description": "Using random module for security-sensitive values is predictable.",
        "patterns": ["random.random(", "random.randint(", "random.choice(", "random.uniform("],
        "severity": "MEDIUM",
        "sink": "random",
        "sanitizers": ["secrets.", "secrets.token_", "crypto.random"]
    },
    {
        "cve": "CVE-2021-29921",
        "cwe": "CWE-798",
        "name": "Hardcoded Secret",
        "description": "Embedding API keys, passwords, or tokens in source code exposes them to anyone with repo access.",
        "patterns": ["API_KEY = \"", "SECRET_KEY = \"", "PASSWORD = \"", "TOKEN = \"", "aws_secret", "private_key = \""],
        "severity": "HIGH",
        "sink": "password",
        "sanitizers": ["os.environ", "os.getenv", "getenv"]
    },
    {
        "cve": "CVE-2022-0391",
        "cwe": "CWE-94",
        "name": "URLLib SSRF",
        "description": "Fetching user-supplied URLs without validation can reach internal services.",
        "patterns": ["urllib.request.urlopen(", "urllib.urlopen(", "requests.get(request.", "requests.get(url)"],
        "severity": "HIGH",
        "sink": "urlopen",
        "sanitizers": ["ipaddress.ip_address", "is_private", "allowed_domains"]
    },
    {
        "cve": "CVE-2023-36632",
        "cwe": "CWE-20",
        "name": "Use of assert for Validation",
        "description": "assert statements are stripped when Python runs with -O, removing the validation.",
        "patterns": ["assert "],
        "severity": "LOW",
        "sink": "assert",
        "sanitizers": ["if not", "raise"]
    }
]

def get_python_rules() -> List[Dict]:
    return PYTHON_RULES
