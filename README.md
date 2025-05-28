# Email Phishing Detector

A full-stack, modern application for detecting and analyzing potential phishing emails by uploading `.eml` files. Designed for security teams, IT admins, and researchers, it provides deep analysis, risk scoring, and actionable threat intelligence for every email and attachment.

**Current Version**: v1.0.2 - Fixed PDF report generation and improved hash display

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
- **Debug Features**: 
  - View raw analysis data in JSON format
  - Access application logs through UI
  - Monitor real-time analysis progress
- **Comprehensive Logging**: 
  - Browser console logging
  - UI-based log viewer
  - Detailed operation tracking

---

## Version History

### v1.0.2 (Current)
- Fixed PDF report generation issues with HTML tags
- Improved hash display in reports (now shows full hash)
- Enhanced table formatting for suspicious elements
- Added better error handling for report generation

### v1.0.1
- Added comprehensive logging system
- Implemented debug features in UI
- Enhanced email analysis capabilities
- Improved UI components
- Removed unused files and directories
- Added Docker support
- Implemented PDF and CSV report generation

---

## Project Structure

```
email-phishing-app/
├── frontend/          # React frontend
│   ├── src/
│   │   ├── components/    # UI components (UploadForm, ResultDisplay, etc.)
│   │   ├── services/      # API, auth, and logging services
│   │   ├── App.js
│   │   └── index.js
│   └── package.json
│
└── backend/           # Flask backend
    ├── app.py
    ├── requirements.txt
    ├── uploads/        # Upload endpoints
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

## Debug Features

### JSON Debug View
- Click "Show Debug JSON" button to view raw analysis data
- Useful for development and troubleshooting
- Shows complete analysis results in JSON format

### Log Viewer
- Access through "View Logs" button in the UI
- Displays application logs in a table format
- Features:
  - Timestamp
  - Log level (color-coded)
  - Message
  - Additional data
- Options to:
  - Clear logs
  - Close viewer
  - Scroll through history

### Browser Console
- Press F12 to open browser developer tools
- View real-time logs in the Console tab
- Color-coded by log level
- Useful for development and debugging

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
- Reports include:
  - Basic email information (subject, from, to)
  - Risk assessment with score and factors
  - Authentication results (SPF, DKIM, DMARC)
  - Threat intelligence data
  - Server hops analysis
  - Attachment details with VirusTotal results
  - Suspicious HTML elements
  - Suspicious language patterns

#### Report Features
- **PDF Reports**:
  - Professional formatting with tables and sections
  - Color-coded risk indicators
  - Truncated hashes for readability
  - Clickable VirusTotal links
  - Automatic page breaks for long content

- **CSV Reports**:
  - Structured data format for analysis
  - Compatible with spreadsheet software
  - Includes all analysis data
  - Easy to import into other tools

#### Download Process
1. Click "Download PDF Report" or "Download CSV Report" button
2. The system will:
   - Validate the analysis data
   - Generate the report
   - Show download progress
   - Handle any errors gracefully
   - Clean up temporary files

#### Error Handling
- Reports handle various error scenarios:
  - Missing or invalid data
  - Network timeouts (30-second limit)
  - File generation errors
  - Download interruptions
  - Invalid content types
  - Empty or corrupted files

#### Security Features
- Reports are generated server-side
- Temporary files are cleaned up automatically
- No sensitive data is stored
- Reports are streamed securely
- Object URLs are properly revoked

To download reports, use:
- Frontend buttons in the analysis results view
- API endpoints:
  - `POST /api/uploads/download/pdf/<filename>`
  - `POST /api/uploads/download/csv/<filename>`

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

## Environment Variables

The application requires several environment variables to function properly. Create a `.env` file in the root directory with the following variables:

```env
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development

# Security
JWT_SECRET_KEY=your_jwt_secret_key_here  # Used for JWT token generation

# API Keys
VT_API_KEY=your_virustotal_api_key_here  # VirusTotal API key for file analysis
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here  # AbuseIPDB API key for IP analysis

# Frontend Configuration
REACT_APP_API_URL=http://localhost:5000  # Backend API URL for frontend
```

### Required API Keys

1. **JWT Secret Key**
   - Used for securing user authentication
   - Should be a strong, random string
   - Example: `JWT_SECRET_KEY=your-random-secret-key-here`

2. **VirusTotal API Key**
   - Required for file hash analysis
   - Get it from: https://www.virustotal.com/
   - Example: `VT_API_KEY=your-virustotal-api-key-here`

3. **AbuseIPDB API Key**
   - Required for IP address analysis
   - Get it from: https://www.abuseipdb.com/
   - Example: `ABUSEIPDB_API_KEY=your-abuseipdb-api-key-here`

### Development vs Production

For development:
```env
FLASK_ENV=development
REACT_APP_API_URL=http://localhost:5000
```

For production:
```env
FLASK_ENV=production
REACT_APP_API_URL=https://your-production-domain.com
```
