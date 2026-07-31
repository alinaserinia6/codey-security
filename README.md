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
