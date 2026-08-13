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
        "ignore_if": ["strcpy_s", "strcat_s", "sprintf_s", "gets_s", "strncpy(", "snprintf(", "strlcpy("],
        "sanitizers": ["strncpy", "snprintf", "strlcpy"]
    },
    {
        "cve": "CVE-2017-7529",
        "cwe": "CWE-190",
        "name": "Integer Overflow",
        "description": "Integer overflow in range processing can lead to information disclosure.",
        "patterns": ["start + length"],
        "severity": "HIGH",
        "sink": "start + length",
        "sanitizers": ["check_overflow"]
    },
    {
        "cve": "N/A",
        "cwe": "CWE-78",
        "name": "Command Injection",
        "description": "Using system() with user input allows command injection.",
        "patterns": ["system("],
        "severity": "CRITICAL",
        "sink": "system",
        "sanitizers": ["execve", "execvp"]
    },
    {
        "cve": "CVE-2022-0847",
        "cwe": "CWE-134",
        "name": "Format String Vulnerability",
        "description": "Passing user input as the format string to printf-family functions allows memory reads/writes.",
        "patterns": ["printf(", "fprintf(", "sprintf(", "snprintf("],
        "severity": "HIGH",
        "sink": "printf",
        "format_args": {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2},
        "sanitizers": ["fprintf(stderr,", "fprintf(stdout,"]
    },
    {
        "cve": "CVE-2019-1543",
        "cwe": "CWE-327",
        "name": "Weak Cryptographic Algorithm",
        "description": "MD5 and SHA1 are cryptographically broken for security-sensitive uses.",
        "patterns": ["MD5(", "SHA1(", "MD5_Init(", "SHA1_Init("],
        "severity": "MEDIUM",
        "sink": "MD5",
        "sanitizers": ["SHA256", "SHA384", "SHA512"]
    },
    {
        "cve": "CVE-2021-3449",
        "cwe": "CWE-295",
        "name": "Disabled TLS Certificate Validation",
        "description": "SSL_VERIFY_NONE disables certificate validation, enabling MITM attacks.",
        "patterns": ["SSL_VERIFY_NONE", "verify = 0"],
        "severity": "HIGH",
        "sink": "SSL_VERIFY_NONE",
        "sanitizers": ["SSL_VERIFY_PEER", "verify = 1"]
    },
    {
        "cve": "CVE-2021-4034",
        "cwe": "CWE-269",
        "name": "Privilege Boundary Violation",
        "description": "Calling setuid(0) without proper authorization checks is dangerous.",
        "patterns": ["setuid(0)", "seteuid(0)", "setgid(0)"],
        "severity": "HIGH",
        "sink": "setuid",
        "sanitizers": ["getuid", "check_priv"]
    },
    {
        "cve": "CVE-2022-0185",
        "cwe": "CWE-787",
        "name": "Out-of-Bounds Write",
        "description": "memcpy/memmove with unchecked sizes can write out of bounds.",
        "patterns": ["memcpy(", "memmove("],
        "severity": "HIGH",
        "sink": "memcpy",
        "sanitizers": ["memcpy_s", "memmove_s", "size check"]
    },
    {
        "cve": "CVE-2021-3493",
        "cwe": "CWE-416",
        "name": "Use-After-Free Risk",
        "description": "Freeing memory and then using the pointer can lead to code execution.",
        "patterns": ["free(", "delete "],
        "severity": "MEDIUM",
        "sink": "free",
        "sanitizers": ["NULL", "= NULL", "set to NULL"]
    }
]

def get_c_rules() -> List[Dict]:
    return C_RULES
