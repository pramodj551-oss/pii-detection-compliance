# 🛡️ PII Detection & Data Privacy Compliance System

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Pandas](https://img.shields.io/badge/Data-Pandas-green?logo=pandas)
![GDPR](https://img.shields.io/badge/Compliance-GDPR-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![PII Types](https://img.shields.io/badge/PII_Types-9-orange)

Automated Python utility that scans enterprise datasets for **9 types of Personally Identifiable Information** and generates GDPR-aligned compliance reports with automatic masking.

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Problem Statement](#problem-statement)
3. [Features](#features)
4. [PII Types Detected](#pii-types-detected)
5. [Sample Input / Output](#sample-input--output)
6. [Project Structure](#project-structure)
7. [Installation](#installation)
8. [Usage](#usage)
9. [Output Files](#output-files)
10. [Configuration](#configuration)
11. [Limitations & Roadmap](#limitations--roadmap)
12. [References](#references)

---

## ⚡ Quick Start

```bash
git clone https://github.com/pramodj551-oss/pii-detection-compliance
cd pii-detection-compliance
pip install -r requirements.txt
python pii_detector.py
```

Output files appear in `results/` folder.

---

## 📌 Problem Statement

Enterprise datasets frequently contain **Personally Identifiable Information (PII)** in free-text fields — log notes, HR records, finance entries — that can lead to:

- **GDPR Article 32** violations — security measures mandatory for personal data
- **IT Act Section 43A** penalties in India
- Data breach costs averaging **₹17 crore per incident** (IBM 2024)
- Manual audits that are **error-prone and time-consuming**

This tool automates the entire detection → reporting → masking pipeline.

---

## ✨ Features

| Feature | Detail |
|--------|--------|
| 🔍 9 PII Types | Aadhaar, PAN, Email, Phone, Credit Card, Password, IP, DOB, Name |
| ⚠️ Severity Levels | CRITICAL / HIGH / MEDIUM classification |
| 🏷️ GDPR Mapping | Each PII type mapped to GDPR data category |
| 📋 Compliance Report | JSON report with violation summary + remediation |
| 🔒 Auto Masking | Replaces PII with `[REDACTED-TYPE]` tags |
| 📁 3 Output Files | JSON report + masked CSV + findings CSV |
| 🏢 Enterprise Dataset | 12-record sample dataset included |
| 📦 No ML Required | Pure regex — no model training needed |

---

## 🔎 PII Types Detected

| PII Type | Severity | GDPR Category | Example Match |
|----------|----------|---------------|---------------|
| `aadhaar` | 🔴 CRITICAL | Government ID | `1234 5678 9012` |
| `pan_card` | 🔴 CRITICAL | Government ID | `ABCDE1234F` |
| `credit_card` | 🔴 CRITICAL | Financial Data | `4532015112830366` |
| `password_field` | 🔴 CRITICAL | Credentials | `password=Admin@123` |
| `email` | 🟠 HIGH | Contact Data | `pramod@example.com` |
| `phone_india` | 🟠 HIGH | Contact Data | `+91-9812345678` |
| `date_of_birth` | 🟠 HIGH | Personal Data | `DOB: 15/08/1990` |
| `ip_address` | 🟡 MEDIUM | Network Identifier | `192.168.1.45` |
| `full_name` | 🟡 MEDIUM | Identity Data | `name=Rahul Sharma` |

---

## 📊 Sample Input / Output

### Input Dataset (from `generate_sample_dataset()`)

| record_id | department | notes |
|-----------|------------|-------|
| REC001 | IT | User pramod@example.com logged in from 192.168.1.45 |
| REC002 | HR | Employee name=Rahul Sharma, DOB: 15/08/1990, Phone: 9876543210 |
| REC003 | Finance | Card: 4532015112830366, PAN: ABCDE1234F |
| REC005 | Admin | password=Admin@123 set for new user |
| REC007 | HR | Aadhaar: 1234 5678 9012 submitted for verification |

### After Masking (`results/masked_dataset.csv`)

| record_id | department | notes |
|-----------|------------|-------|
| REC001 | IT | User **[REDACTED-EMAIL]** logged in from **[REDACTED-IP_ADDRESS]** |
| REC002 | HR | Employee **[REDACTED-FULL_NAME]**, **[REDACTED-DATE_OF_BIRTH]**, Phone: **[REDACTED-PHONE_INDIA]** |
| REC003 | Finance | Card: **[REDACTED-CREDIT_CARD]**, PAN: **[REDACTED-PAN_CARD]** |
| REC005 | Admin | **[REDACTED-PASSWORD_FIELD]** set for new user |
| REC007 | HR | Aadhaar: **[REDACTED-AADHAAR]** submitted for verification |

### Compliance Report (`results/pii_compliance_report.json`)

```json
{
  "generated_at": "2026-05-11T10:30:00",
  "records_scanned": 12,
  "pii_violations": 11,
  "records_affected": 7,
  "gdpr_compliant": false,
  "findings": [
    {
      "record_id": "REC001",
      "column": "notes",
      "pii_type": "email",
      "severity": "HIGH",
      "gdpr_category": "Contact Data",
      "match_count": 1,
      "sample_match": "pramod@example.com",
      "action_needed": "MASK / REDACT"
    }
  ]
}
```

### Console Report Output

```
=======================================================
  PII DETECTION — GDPR COMPLIANCE REPORT
=======================================================
  Records scanned  : 12
  PII violations   : 11
  Records affected : 7
  CRITICAL items   : 5
  HIGH items       : 4
  MEDIUM items     : 2

  PII BREAKDOWN BY TYPE:

  [CRITICAL] aadhaar              | Government ID       | Found: 1
  [CRITICAL] credit_card          | Financial Data      | Found: 1
  [CRITICAL] pan_card             | Government ID       | Found: 1
  [CRITICAL] password_field       | Credentials         | Found: 1
  [HIGH    ] date_of_birth        | Personal Data       | Found: 1
  [HIGH    ] email                | Contact Data        | Found: 1
  [HIGH    ] phone_india          | Contact Data        | Found: 2
  [MEDIUM  ] full_name            | Identity Data       | Found: 1
  [MEDIUM  ] ip_address           | Network Identifier  | Found: 2
=======================================================
```

---

## 📁 Project Structure

```
pii-detection-compliance/
├── pii_detector.py          # Main script — all logic in one file
├── requirements.txt         # Dependencies
├── .gitignore
├── README.md
└── results/                 # Auto-created on first run
    ├── pii_compliance_report.json   # GDPR compliance summary
    ├── masked_dataset.csv           # PII-redacted output
    └── pii_findings.csv             # Row-level findings
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.10+
- pip

### Steps

```bash
# 1. Clone
git clone https://github.com/pramodj551-oss/pii-detection-compliance
cd pii-detection-compliance

# 2. Virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux

# 3. Install
pip install -r requirements.txt
```

---

## 💻 Usage

### Option A — Run on Sample Dataset

```bash
python pii_detector.py
```

Scans the built-in 12-record enterprise dataset. Results saved to `results/`.

### Option B — Scan Your Own CSV

Replace `generate_sample_dataset()` in `main()`:

```python
# In pii_detector.py — main() function, line [1/4]:
df = pd.read_csv("your_dataset.csv")          # ← replace this line
```

### Option C — Use as Module

```python
from pii_detector import scan_dataframe, apply_masking, generate_compliance_report
import pandas as pd

df       = pd.read_csv("enterprise_data.csv")
findings = scan_dataframe(df, text_columns=["notes", "comments", "description"])
generate_compliance_report(df, findings)
masked   = apply_masking(df, text_columns=["notes", "comments"])
masked.to_csv("results/masked_output.csv", index=False)
```

---

## 📂 Output Files

| File | Content |
|------|---------|
| `results/pii_compliance_report.json` | Summary: records scanned, violations, GDPR status, full findings |
| `results/masked_dataset.csv` | Original data with PII replaced by `[REDACTED-TYPE]` |
| `results/pii_findings.csv` | Row-level: which record, column, PII type, severity |

---

## ⚙️ Configuration

Edit `PII_PATTERNS` dict in `pii_detector.py` to customize:

```python
PII_PATTERNS = {
    "email": {
        "pattern":       r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
        "severity":      "HIGH",           # CRITICAL / HIGH / MEDIUM
        "gdpr_category": "Contact Data"
    },
    # Add your own PII type:
    "employee_id": {
        "pattern":       r'\bEMP\d{5}\b',
        "severity":      "MEDIUM",
        "gdpr_category": "Identity Data"
    }
}
```

---

## ⚠️ Limitations & Roadmap

**Current Limitations:**
- Regex-based — limited context awareness (may have false positives)
- India-focused PII (Aadhaar, PAN, Indian phone format)
- No ML-based Named Entity Recognition (NER)

**Planned Enhancements:**
- [ ] NLP/spaCy-based PII detection for names
- [ ] Multi-language support
- [ ] Streamlit dashboard with visual report
- [ ] Real-time REST API endpoint (Flask)
- [ ] Configurable masking strategies (partial mask vs full redact)
- [ ] International PII — SSN (US), NIN (UK), ABN (AU)

---

## 📚 References

- [GDPR Article 32 — Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [IT Act Section 43A — India](https://www.meity.gov.in)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)

---

## 🤝 Contributing

1. Fork → `git checkout -b feature/add-nlp-detection`
2. Commit → `git commit -m 'Add spaCy NER for name detection'`
3. Push → `git push origin feature/add-nlp-detection`
4. Open a Pull Request

---

## 📝 License

MIT License — see [LICENSE](LICENSE)

---

## 📧 Contact

**Pramod** · IIT Patna Applied AI & ML Program  
GitHub: [@pramodj551-oss](https://github.com/pramodj551-oss)

> ⭐ Star this repo if it helped you!
