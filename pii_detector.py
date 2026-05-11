"""
PII Detection & Data Privacy Compliance System
================================================
Author  : Pramod Prakash Jadhav
GitHub  : github.com/pramodj551-oss
LinkedIn: linkedin.com/in/pramod-jadhav-42ba2281

Scans enterprise datasets for Personally Identifiable Information (PII)
and generates GDPR-aligned compliance reports.

Detects: Names, Emails, Phone Numbers, Aadhaar, PAN, Passwords,
         IP Addresses, Credit Cards, Dates of Birth, Addresses
"""

import pandas as pd
import numpy as np
import re
import json
import os
from datetime import datetime

# ── PII DETECTION RULES ──────────────────────────────────
PII_PATTERNS = {
    "email": {
        "pattern": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
        "severity": "HIGH",
        "gdpr_category": "Contact Data"
    },
    "phone_india": {
        "pattern": r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b',
        "severity": "HIGH",
        "gdpr_category": "Contact Data"
    },
    "aadhaar": {
        "pattern": r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
        "severity": "CRITICAL",
        "gdpr_category": "Government ID"
    },
    "pan_card": {
        "pattern": r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        "severity": "CRITICAL",
        "gdpr_category": "Government ID"
    },
    "credit_card": {
        "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        "severity": "CRITICAL",
        "gdpr_category": "Financial Data"
    },
    "ip_address": {
        "pattern": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "severity": "MEDIUM",
        "gdpr_category": "Network Identifier"
    },
    "date_of_birth": {
        "pattern": r'\b(?:DOB|dob|Date of Birth|birth_date)[\s:]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b',
        "severity": "HIGH",
        "gdpr_category": "Personal Data"
    },
    "password_field": {
        "pattern": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+',
        "severity": "CRITICAL",
        "gdpr_category": "Credentials"
    },
    "full_name": {
        "pattern": r'\b(?:name|full_name|employee_name)\s*[:=]\s*[A-Z][a-z]+\s[A-Z][a-z]+\b',
        "severity": "MEDIUM",
        "gdpr_category": "Identity Data"
    }
}


# ── SAMPLE DATA GENERATOR ─────────────────────────────────
def generate_sample_dataset():
    """
    Creates a realistic enterprise dataset with both clean and PII-containing records.
    Replace with pd.read_csv("your_file.csv") for real usage.
    """
    data = [
        {"record_id": "REC001", "department": "IT",       "notes": "User pramod@example.com logged in from 192.168.1.45"},
        {"record_id": "REC002", "department": "HR",        "notes": "Employee name=Rahul Sharma, DOB: 15/08/1990, Phone: 9876543210"},
        {"record_id": "REC003", "department": "Finance",   "notes": "Card: 4532015112830366, PAN: ABCDE1234F"},
        {"record_id": "REC004", "department": "IT",        "notes": "Server patch completed successfully. No issues."},
        {"record_id": "REC005", "department": "Admin",     "notes": "password=Admin@123 set for new user"},
        {"record_id": "REC006", "department": "Security",  "notes": "Alert from 10.0.0.22 — multiple failed logins"},
        {"record_id": "REC007", "department": "HR",        "notes": "Aadhaar: 1234 5678 9012 submitted for verification"},
        {"record_id": "REC008", "department": "IT",        "notes": "Firewall rules updated. Access logs rotated."},
        {"record_id": "REC009", "department": "Finance",   "notes": "Contact: +91-9812345678 for invoice queries"},
        {"record_id": "REC010", "department": "Security",  "notes": "Routine perimeter check completed. No anomalies."},
        {"record_id": "REC011", "department": "HR",        "notes": "full_name=Sneha Patil joined the Data team"},
        {"record_id": "REC012", "department": "IT",        "notes": "Backup completed at 02:00. All systems normal."},
    ]
    return pd.DataFrame(data)


# ── SCANNER ──────────────────────────────────────────────
def scan_dataframe(df, text_columns=None):
    """
    Scans all string columns in a DataFrame for PII patterns.
    Returns a detailed findings DataFrame.
    """
    if text_columns is None:
        text_columns = df.select_dtypes(include="object").columns.tolist()

    findings = []

    for col in text_columns:
        for idx, value in df[col].dropna().items():
            for pii_type, config in PII_PATTERNS.items():
                matches = re.findall(config["pattern"], str(value))
                if matches:
                    findings.append({
                        "record_id":    df.get("record_id", pd.Series([idx])).iloc[idx] if "record_id" in df.columns else idx,
                        "column":       col,
                        "pii_type":     pii_type,
                        "severity":     config["severity"],
                        "gdpr_category": config["gdpr_category"],
                        "match_count":  len(matches),
                        "sample_match": matches[0][:20] + "..." if len(str(matches[0])) > 20 else matches[0],
                        "action_needed": "MASK / REDACT"
                    })

    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ── MASKING ──────────────────────────────────────────────
def mask_pii(text):
    """
    Masks detected PII in a string with [REDACTED] placeholders.
    """
    for pii_type, config in PII_PATTERNS.items():
        text = re.sub(config["pattern"], f"[REDACTED-{pii_type.upper()}]", str(text))
    return text


def apply_masking(df, text_columns=None):
    """
    Returns a copy of the DataFrame with PII masked.
    """
    if text_columns is None:
        text_columns = df.select_dtypes(include="object").columns.tolist()
        text_columns = [c for c in text_columns if c != "record_id"]

    masked_df = df.copy()
    for col in text_columns:
        masked_df[col] = masked_df[col].apply(lambda x: mask_pii(x) if pd.notna(x) else x)
    return masked_df


# ── REPORT ───────────────────────────────────────────────
def generate_compliance_report(df_original, findings_df):
    """
    Prints a GDPR compliance summary and saves JSON report.
    """
    print("\n" + "="*55)
    print("  PII DETECTION — GDPR COMPLIANCE REPORT")
    print("="*55)
    print(f"  Records scanned  : {len(df_original)}")

    if findings_df.empty:
        print("  PII detected     : NONE — Dataset is clean ✓")
    else:
        print(f"  PII violations   : {len(findings_df)}")
        print(f"  Records affected : {findings_df['record_id'].nunique()}")
        print(f"  CRITICAL items   : {len(findings_df[findings_df['severity']=='CRITICAL'])}")
        print(f"  HIGH items       : {len(findings_df[findings_df['severity']=='HIGH'])}")
        print(f"  MEDIUM items     : {len(findings_df[findings_df['severity']=='MEDIUM'])}")
        print("\n  PII BREAKDOWN BY TYPE:\n")
        summary = findings_df.groupby(["pii_type","severity","gdpr_category"]).size().reset_index(name="count")
        for _, row in summary.iterrows():
            print(f"  [{row['severity']:8s}] {row['pii_type']:20s} | {row['gdpr_category']:20s} | Found: {row['count']}")

    print("="*55)

    # Save report
    os.makedirs("results", exist_ok=True)
    report = {
        "generated_at":     datetime.now().isoformat(),
        "records_scanned":  len(df_original),
        "pii_violations":   len(findings_df),
        "records_affected": int(findings_df["record_id"].nunique()) if not findings_df.empty else 0,
        "gdpr_compliant":   findings_df.empty,
        "findings":         findings_df.to_dict(orient="records") if not findings_df.empty else []
    }
    with open("results/pii_compliance_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n  Report saved → results/pii_compliance_report.json")
    print("="*55 + "\n")


# ── MAIN ────────────────────────────────────────────────
def main():
    print("\n[1/4] Loading dataset...")
    df = generate_sample_dataset()
    print(f"      {len(df)} records loaded.")

    print("[2/4] Scanning for PII patterns...")
    findings = scan_dataframe(df, text_columns=["notes"])
    print(f"      Scan complete — {len(findings)} PII instances found.")

    print("[3/4] Generating compliance report...")
    generate_compliance_report(df, findings)

    print("[4/4] Applying PII masking...")
    masked_df = apply_masking(df, text_columns=["notes"])
    os.makedirs("results", exist_ok=True)
    masked_df.to_csv("results/masked_dataset.csv", index=False)
    findings.to_csv("results/pii_findings.csv", index=False) if not findings.empty else None
    print("  Masked dataset saved → results/masked_dataset.csv")
    print("  PII findings saved   → results/pii_findings.csv\n")


if __name__ == "__main__":
    main()
                  
