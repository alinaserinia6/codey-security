# codey-security
## 🔒 Multi-Agent Code Vulnerability Scanner

یک ابزار تحلیل ایستای کد مبتنی بر عامل‌های هوشمند برای شناسایی آسیب‌پذیری‌های امنیتی.

## 🎯 ویژگی‌ها

- **تحلیل ایستای کد** با استفاده از Tree-sitter
- **معماری دو-عامله**: Scanner Agent + Verifier Agent
- **پشتیبانی از زبان‌های Python و C**
- **شناسایی آسیب‌پذیری‌های واقعی** با تأیید جریان داده
- **خروجی JSON** برای گزارش‌گیری
- **قابل گسترش** برای افزودن قوانین و CVEهای جدید

## 📦 نصب

```bash
# Clone repository
git clone <repository-url>
cd codey-security

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 🚀 استفاده
اسکن یک فایل
```bash
python main.py samples/vulnerable_python.py
```
اسکن یک دایرکتوری
```bash
python main.py samples/ -r
```
ذخیره گزارش
```bash
python main.py samples/vulnerable_python.py -o output/reports/
```
## 📊 خروجی نمونه
```text
============================================================
📊 Vulnerability Report: samples/vulnerable_python.py
   Language: python
============================================================

📈 Summary:
   Total findings: 3
   ✅ Confirmed: 2
   ❌ Unconfirmed: 1

🔍 Detailed Findings:

   1. ✅ Server-Side Template Injection (CVE-2021-25239)
      CWE: CWE-94
      Location: samples/vulnerable_python.py:15
      Severity: CRITICAL
      Evidence: Found pattern 'render_template_string' at lines [15]. This matches Server-Side Template Injection (CVE-2021-25239). No sanitizer found - potential vulnerability. ✅ Verified: Data flow confirmed.

   2. ✅ Unsafe YAML Deserialization (CVE-2022-22817)
      CWE: CWE-502
      Location: samples/vulnerable_python.py:22
      Severity: CRITICAL
      Evidence: Found pattern 'yaml.unsafe_load' at lines [22]. This matches Unsafe YAML Deserialization (CVE-2022-22817). No sanitizer found - potential vulnerability. ✅ Verified: Data flow confirmed.
============================================================
```

## 🧪 اجرای تست‌ها

```bash
python -m pytest tests/
📁 ساختار پروژه
text
vulnerability-scanner/
├── README.md
├── requirements.txt
├── config.py
├── main.py
├── core/
│   ├── parser.py          # Tree-sitter parser
│   ├── scanner_agent.py   # شناسایی الگوها
│   ├── verifier_agent.py  # تأیید جریان داده
│   └── models.py          # مدل‌های داده
├── rules/
│   ├── python_rules.py    # قوانین Python
│   └── c_rules.py         # قوانین C
├── samples/
│   ├── vulnerable_python.py
│   └── vulnerable_c.c
└── tests/
    └── test_scanner.py
🔧 افزودن قوانین جدید
برای افزودن یک CVE جدید، کافی است به فایل قوانین مربوطه اضافه کنید:

python
# در rules/python_rules.py
{
    "cve": "CVE-2023-XXXXX",
    "cwe": "CWE-XXX",
    "name": "نام آسیب‌پذیری",
    "description": "توضیحات",
    "patterns": ["pattern1", "pattern2"],
    "severity": "CRITICAL",
    "sink": "function_name",
    "sanitizers": ["safe_function"]
}
```
