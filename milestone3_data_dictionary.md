# Email Phishing Detection System - Data Dictionary

## Users Table

### Field Definitions
Field Name | Data Type | Description | Constraints | Example
-----------|-----------|-------------|-------------|---------
id | SERIAL | Unique identifier for the user | PRIMARY KEY | 1
email | VARCHAR(255) | User's email address | UNIQUE, NOT NULL | user@example.com
password_hash | VARCHAR(255) | Hashed password | NOT NULL | $2a$10$...
created_at | TIMESTAMP | Account creation timestamp | DEFAULT CURRENT_TIMESTAMP | 2024-01-01 12:00:00
last_login | TIMESTAMP | Last login timestamp | NULLABLE | 2024-01-02 15:30:00

### Relationships
- One-to-many relationship with Analyses table
- One-to-many relationship with Reports table

## Analyses Table

### Field Definitions
Field Name | Data Type | Description | Constraints | Example
-----------|-----------|-------------|-------------|---------
id | SERIAL | Unique identifier for the analysis | PRIMARY KEY | 1
user_id | INTEGER | Reference to user who performed analysis | FOREIGN KEY | 1
filename | VARCHAR(255) | Original filename of uploaded .eml | NOT NULL | suspicious_email.eml
results | JSONB | Analysis results in JSON format | NULLABLE | {"risk_score": 0.85, "threats": [...]}
created_at | TIMESTAMP | Analysis creation timestamp | DEFAULT CURRENT_TIMESTAMP | 2024-01-01 12:00:00
status | VARCHAR(50) | Current status of analysis | NOT NULL | completed

### Relationships
- Many-to-one relationship with Users table
- One-to-many relationship with Reports table

## Reports Table

### Field Definitions
Field Name | Data Type | Description | Constraints | Example
-----------|-----------|-------------|-------------|---------
id | SERIAL | Unique identifier for the report | PRIMARY KEY | 1
analysis_id | INTEGER | Reference to associated analysis | FOREIGN KEY | 1
format | VARCHAR(50) | Report format (PDF/CSV) | NOT NULL | PDF
path | VARCHAR(255) | File system path to report | NOT NULL | /reports/1.pdf
generated_at | TIMESTAMP | Report generation timestamp | DEFAULT CURRENT_TIMESTAMP | 2024-01-01 12:00:00

### Relationships
- Many-to-one relationship with Analyses table

## Analysis Results JSON Structure

### Root Object
```json
{
    "risk_score": "float",
    "metadata": {
        "from": "string",
        "to": "string",
        "subject": "string",
        "date": "string"
    },
    "authentication": {
        "spf": "boolean",
        "dkim": "boolean",
        "dmarc": "boolean"
    },
    "threats": [
        {
            "type": "string",
            "description": "string",
            "severity": "string"
        }
    ],
    "attachments": [
        {
            "filename": "string",
            "type": "string",
            "size": "integer",
            "hash": "string",
            "risk_level": "string"
        }
    ],
    "links": [
        {
            "url": "string",
            "domain": "string",
            "risk_level": "string",
            "redirects": "integer"
        }
    ]
}
```

## Enumerated Types

### Status Types
Value | Description
------|------------
pending | Analysis is queued for processing
processing | Analysis is currently being performed
completed | Analysis has finished successfully
failed | Analysis encountered an error

### Risk Levels
Value | Description
------|------------
low | Minimal risk detected
medium | Moderate risk detected
high | Significant risk detected
critical | Severe risk detected

### Report Formats
Value | Description
------|------------
PDF | Portable Document Format
CSV | Comma-Separated Values

## Data Validation Rules

### Email Format
- Must match standard email format (RFC 5322)
- Maximum length: 255 characters
- Must be unique in the system

### Password Requirements
- Minimum length: 8 characters
- Must contain at least one uppercase letter
- Must contain at least one lowercase letter
- Must contain at least one number
- Must contain at least one special character

### Filename Requirements
- Maximum length: 255 characters
- Must end with .eml extension
- Must not contain special characters except -_.
- Must not be empty

## Data Retention Policy

### Users
- Active accounts: Indefinite
- Inactive accounts (no login for 1 year): 30 days after notification
- Deleted accounts: 90 days in archive

### Analyses
- Completed analyses: 1 year
- Failed analyses: 30 days
- Pending analyses: 7 days

### Reports
- Generated reports: 1 year
- Failed generations: 7 days

## Data Security

### Encryption
- Passwords: bcrypt with salt
- Sensitive data: AES-256
- Communication: TLS 1.3

### Access Control
- User data: Owner only
- Analysis results: Owner only
- Reports: Owner only
- System logs: Administrators only

## Data Backup
- Daily incremental backups
- Weekly full backups
- Monthly archive backups
- Backup retention: 1 year 