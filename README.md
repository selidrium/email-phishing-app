# Email Phishing Detector

A full-stack, modern application for detecting and analyzing potential phishing emails by uploading `.eml` files. Designed for security teams, IT admins, and researchers, it provides deep analysis, risk scoring, and actionable threat intelligence for every email and attachment.

---

## Features

- **User Authentication**: Register, login, and password reset with JWT-secured endpoints.
- **.eml File Upload & Analysis**: Upload email files for instant, automated analysis.
- **Per-Attachment Threat Intelligence**:
  - Each attachment is individually hashed (SHA-256).
  - Hashes are checked against VirusTotal for known threats.
  - Results (hash, VirusTotal status, detection count) are shown in the frontend and included in PDF reports.
- **Threat Intelligence Integration**:
  - VirusTotal (file hashes)
  - AbuseIPDB (server hop IPs)
- **Risk Scoring System**: Emails are scored 0-100 based on authentication, content, attachments, and threat intelligence.
- **PDF & CSV Report Generation**: Download detailed analysis reports for archiving or sharing.
- **Modern React Frontend**: Clean, responsive UI for uploading, viewing, and downloading results.
- **Docker Support**: Easy deployment with Docker Compose.

---

## Project Structure

```
email-phishing-app/
├── frontend/          # React frontend
│   ├── src/
│   │   ├── components/    # UI components (UploadForm, ResultDisplay, etc.)
│   │   ├── services/      # API and auth services
│   │   ├── App.js
│   │   └── index.js
│   └── package.json
│
└── backend/           # Flask backend
    ├── app.py
    ├── requirements.txt
    ├── auth/           # Auth endpoints
    ├── uploads/        # Upload endpoints
    ├── models/         # (Optional) DB models
    ├── analysis/       # Email parsing and analysis
    └── utils/          # Threat intelligence, report generation, etc.
```

---

## Setup

### Local Development

1. **Clone the repository:**
   ```bash
git clone <repository-url>
cd email-phishing-app
```
2. **Set up the backend:**
   ```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```
3. **Set up the frontend:**
   ```bash
cd ../frontend
npm install
```
4. **Create a `.env` file in the backend directory:**
   ```
FLASK_APP=app.py
FLASK_ENV=development
JWT_SECRET_KEY=your_jwt_secret_key_here
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```
5. **Run the applications:**
   - Backend: `python app.py` (in backend directory)
   - Frontend: `npm start` (in frontend directory)

### Docker Deployment

1. **Create a `.env` file in the root or backend directory** (see above).
2. **Build and run with Docker Compose:**
   ```bash
docker-compose up --build
```

---

## Getting API Keys

### VirusTotal API Key
1. Go to https://www.virustotal.com/
2. Create an account or sign in
3. Go to your profile and request an API key
4. Add the API key to your `.env` file as `VT_API_KEY`

### AbuseIPDB API Key
1. Go to https://www.abuseipdb.com/
2. Create an account or sign in
3. Go to your account settings and generate an API key
4. Add the API key to your `.env` file as `ABUSEIPDB_API_KEY`

---

## Risk Scoring System

The application calculates a risk score (0-100) based on:
- SPF/DKIM/DMARC authentication failures
- Suspicious links (URL shorteners, known malicious domains)
- Dangerous attachments (VirusTotal results)
- Malicious server hops (AbuseIPDB)
- Suspicious HTML or language patterns

**Risk Score Color Coding:**
- Green (0-30): Low risk
- Yellow (31-70): Medium risk
- Red (71-100): High risk

---

## Per-Attachment Threat Intelligence

### How it Works
- When you upload an email, the backend extracts all attachments.
- For each attachment:
  - Computes a SHA-256 hash.
  - Checks the hash against VirusTotal.
  - VirusTotal response includes scan status, detection count (positives/total), and a permalink to the full report.
- The frontend and PDF reports display this information in a dedicated Attachments table.

### Example: Attachments Table

| Filename                  | Type                      | Size | Hash (truncated)                | VirusTotal Status                  | Detection Count |
|---------------------------|---------------------------|------|----------------------------------|------------------------------------|----------------|
| MacOS.Stealer.Banshee.7z  | application/x-7z-compressed | N/A  | 18a99694b5dd26d9...              | [Scan finished, information embedded](https://www.virustotal.com/gui/file/18a99694b5dd26d9341e073122dbc897a32baea8d1ab4e0d56e8da8815167b5c/detection/f-18a99694b5dd26d9341e073122dbc897a32baea8d1ab4e0d56e8da8815167b5c-1732570130) | 0/61           |

- The VirusTotal status is a clickable badge/link to the full report.
- Detection count shows how many engines flagged the file as malicious.

### Example API Response

```json
{
  "attachments": {
    "attachments": [
      {
        "content_type": "application/x-7z-compressed",
        "filename": "MacOS.Stealer.Banshee.7z",
        "hash": "18a99694b5dd26d9341e073122dbc897a32baea8d1ab4e0d56e8da8815167b5c",
        "virustotal": {
          "permalink": "https://www.virustotal.com/gui/file/18a99694b5dd26d9341e073122dbc897a32baea8d1ab4e0d56e8da8815167b5c/detection/f-18a99694b5dd26d9341e073122dbc897a32baea8d1ab4e0d56e8da8815167b5c-1732570130",
          "positives": 0,
          "total": 61,
          "verbose_msg": "Scan finished, information embedded",
          "response_code": 1
        }
      }
    ]
  },
  ...
}
```

### PDF & CSV Report Generation
- After analysis, you can download a PDF or CSV report for any email.
- The PDF includes all analysis sections, including a detailed Attachments table with hash, VirusTotal status, and detection count.
- Use the frontend or call:
  - `GET /uploads/download/pdf/<filename>`
  - `GET /uploads/download/csv/<filename>`

---

## Security & Privacy Notes
- Uploaded emails and attachments are only processed in memory for analysis and reporting.
- Raw attachment data is **never** sent to the frontend or stored long-term.
- Only hashes and scan results are included in API responses and reports.
- For production, use HTTPS, secure API keys, and follow best security practices.

---

## API Endpoints

### Authentication
- `POST /auth/register` — Register a new user
- `POST /auth/login` — Login
- `POST /auth/reset-password` — Request password reset
- `GET /auth/me` — Get current user info

### File Upload and Analysis
- `POST /uploads/upload` — Upload and analyze .eml file
- `GET /uploads/download/pdf/<filename>` — Download PDF report
- `GET /uploads/download/csv/<filename>` — Download CSV report

---

## Developer & Contributor Notes

- **Extending Analysis:**
  - Add new analysis modules in `backend/analysis/`.
  - Add new threat intelligence sources in `backend/utils/threat_intelligence.py`.
- **Testing:**
  - Use sample `.eml` files in `backend/uploads/` for testing.
  - Add unit tests for backend logic.
- **Frontend:**
  - UI components are in `frontend/src/components/`.
  - API and auth logic in `frontend/src/services/`.
- **Deployment:**
  - Use Docker Compose for easy deployment.
  - Set all secrets and API keys via environment variables.

---

## Best Practices & Tips

- Always use strong, unique API keys and secrets.
- Regularly update dependencies for security.
- For production, use a real database and enable HTTPS.
- Monitor and rate-limit API usage, especially for VirusTotal.
- Review and clean up uploaded files and reports regularly.

---

## License

MIT License. See `LICENSE` file for details. 