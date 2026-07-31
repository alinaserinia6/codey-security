#!/usr/bin/env python3
"""
Intentionally vulnerable Python code for demonstration.
Contains SSTI and unsafe deserialization vulnerabilities.
"""

from flask import Flask, request, render_template_string
import yaml
import pickle

app = Flask(__name__)

# VULNERABILITY 1: Server-Side Template Injection (CVE-2021-25239)
@app.route('/render', methods=['POST'])
def render_template_vulnerable():
    user_template = request.form.get('template', '')
    # DANGEROUS: User input passed directly to render_template_string
    rendered = render_template_string(user_template)  # CVE-2021-25239
    return f"Rendered: {rendered}"

# VULNERABILITY 2: Unsafe YAML Deserialization (CVE-2022-22817)
@app.route('/config', methods=['POST'])
def upload_config():
    yaml_content = request.data.decode('utf-8')
    # DANGEROUS: unsafe_load allows arbitrary code execution
    config = yaml.unsafe_load(yaml_content)  # CVE-2022-22817
    return {'status': 'uploaded', 'config': config}

# VULNERABILITY 3: Dynamic Code Execution
@app.route('/eval', methods=['POST'])
def eval_code():
    expression = request.form.get('expr', '')
    # DANGEROUS: eval with user input
    result = eval(expression)  # CWE-95
    return {'result': result}

# SAFE version (for comparison)
@app.route('/render-safe', methods=['POST'])
def render_template_safe():
    user_template = request.form.get('template', '')
    # SAFE: Escape user input
    from markupsafe import escape
    safe_template = escape(user_template)
    return f"Safe: {safe_template}"

# SAFE YAML loading
@app.route('/config-safe', methods=['POST'])
def upload_config_safe():
    yaml_content = request.data.decode('utf-8')
    # SAFE: Use safe_load
    config = yaml.safe_load(yaml_content)
    return {'status': 'uploaded', 'config': config}

if __name__ == '__main__':
    app.run(debug=True)
