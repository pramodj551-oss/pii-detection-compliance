# 🛡️ PII Detection & Data Privacy Compliance System

**Author:** Pramod Prakash Jadhav  
**GitHub:** [github.com/pramodj551-oss](https://github.com/pramodj551-oss)  
**LinkedIn:** [linkedin.com/in/pramod-jadhav-42ba2281](https://linkedin.com/in/pramod-jadhav-42ba2281)

---

## 📌 Problem

Enterprise security datasets often contain **unmasked Personally Identifiable Information (PII)** — employee names, Aadhaar numbers, phone numbers, passwords — creating serious **GDPR and IT Act compliance risk**.

Manual scanning of large datasets was impractical and inconsistent.

## 💡 Solution

Built a **Python/Pandas-based PII detection utility** with configurable regex rules that automatically scans datasets, flags violations by severity, and masks sensitive data — generating a full compliance report.

## 📊 Real-World Impact

| Metric | Result |
|---|---|
| PII categories detected | **9 types** (Aadhaar, PAN, Email, Phone, etc.) |
| Compliance standard | **GDPR-aligned** |
| Output | Masked CSV + JSON compliance report |
| Manual audit time | **Significantly reduced** |

---

## 🔍 PII Types Detected

| Type | Severity | GDPR Category |
|---|---|---|
| Aadhaar Number | 🔴 CRITICAL | Government ID |
| PAN Card | 🔴 CRITICAL | Government ID |
| Credit Card | 🔴 CRITICAL | Financial Data |
| Password Fields | 🔴 CRITICAL | Credentials |
| Email Address | 🟠 HIGH | Contact Data |
| Phone Number (India) | 🟠 HIGH | Contact Data |
| Date of Birth | 🟠 HIGH | Personal Data |
| IP Address | 🟡 MEDIUM | Network Identifier |
| Full Name | 🟡 MEDIUM | Identity Data |

---

## 🛠️ Tech Stack

- **Python 3.9+**
- **Pandas** — dataset processing
- **re (Regex)** — pattern matching
- **JSON** — compliance report output

---

## 🚀 How to Run

```bash
# 1. Clone the repo
git clone https://github.com/pramodj551-oss/pii-detection-compliance
cd pii-detection-compliance

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run on sample data
python pii_detector.py

# 4. Run on your own CSV
# Edit pii_detector.py → replace generate_sample_dataset() with:
# df = pd.read_csv("your_file.csv")
```

---

## 📁 Output Files

```
results/
├── pii_compliance_report.json  ← Full GDPR compliance report
├── pii_findings.csv            ← All detected PII with severity
└── masked_dataset.csv          ← Clean dataset with PII masked
```

---

## 📁 Project Structure

```
pii-detection-compliance/
│
├── pii_detector.py       ← Main detection script
├── requirements.txt      ← Dependencies
├── README.md             ← This file
└── results/              ← Auto-generated outputs
```

---

## 🎓 Learning Context

Built as part of the **Applied AI & ML Essentials** program at **IIT Patna (Vishlesan i-Hub)**, applied to real enterprise security data privacy challenges.

---

*Part of my AI Security portfolio — [portfolio-eta-ashen-pxpaf816ec.vercel.app](https://portfolio-eta-ashen-pxpaf816ec.vercel.app)*
