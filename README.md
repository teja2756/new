# Secure PII Data Storage & Dynamic Masking System

Private portfolio project based on Ts's supplied project specification.

## Features
- TOTP MFA
- RBAC concepts: Admin, HR, Employee, SOC Analyst
- AES-256-GCM encrypted storage
- SHA-256 integrity digest
- Regex-based PII detection
- Dynamic masking for unauthorized display
- SQLite storage and audit logging

## Architecture
Web UI -> MFA -> RBAC -> PII Detection -> AES-256-GCM -> Masking -> Database -> Audit/SIEM

## Run
python -m venv .venv
pip install -r requirements.txt
python app.py

Copy .env.example to .env and configure strong secrets. Never commit .env or real PII.

This is a reconstructed working prototype based on the supplied project specification, not a claim that these files are the user's original source archive.

The design is aligned with relevant ISO/IEC 27001 security principles such as access control, cryptography, logging, least privilege and monitoring; it is not an ISO certification.