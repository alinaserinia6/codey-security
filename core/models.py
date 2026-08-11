from pydantic import BaseModel
from typing import List, Optional
from enum import StrEnum

class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Vulnerability(BaseModel):
    cve: str
    cwe: str
    name: str
    description: str
    location: str  # file:line
    severity: Severity
    evidence: str  # Explanation of data flow
    confirmed: bool = False

class AnalysisReport(BaseModel):
    file_path: str
    language: str
    vulnerabilities: List[Vulnerability]
    summary: dict