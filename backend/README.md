# Email Phishing Detector Backend

A Flask-based API for detecting potential phishing emails by analyzing .eml files.

## Project Structure

```
backend/
├── app.py              # Main application entry point
├── requirements.txt    # Python dependencies
├── auth/              # Authentication routes
├── uploads/           # File upload handling
├── models/            # Data models
├── analysis/          # Email parsing and analysis
└── utils/             # Helper functions
```

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file with the following content:
```
JWT_SECRET_KEY=your-secret-key-here
```

4. Run the application:
```bash
python app.py
```

## API Endpoints

### Authentication

- `POST /auth/register` - Register a new user
  - Body: `{"email": "user@example.com", "password": "password123"}`

- `POST /auth/login` - Login
  - Body: `{"email": "user@example.com", "password": "password123"}`

- `POST /auth/reset-password` - Request password reset
  - Body: `{"email": "user@example.com"}`

- `GET /auth/me` - Get current user info
  - Headers: `Authorization: Bearer <token>`

### File Upload

- `POST /uploads/upload` - Upload and analyze .eml file
  - Headers: `Authorization: Bearer <token>`
  - Body: Form data with `file` field containing .eml file

## Response Format

The upload endpoint returns a JSON response with the following structure:

```json
{
    "message": "File uploaded and analyzed successfully",
    "analysis": {
        "subject": "Email Subject",
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "urls": ["http://example.com", "https://example.org"],
        "server_hops": [
            {
                "header": "Received: from server1.example.com",
                "ip_addresses": ["192.168.1.1"]
            }
        ]
    }
}
```

## Security Notes

- This is a development version. For production:
  - Use a proper database instead of in-memory storage
  - Implement proper password reset functionality
  - Add rate limiting
  - Use HTTPS
  - Implement proper file cleanup 