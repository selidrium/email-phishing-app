# 🛡️ Phishing Email Detection Micro SaaS

A comprehensive, production-ready Micro SaaS application for phishing email detection with advanced security features, structured logging, and VirusTotal integration.

## 📐 Architecture

```
[ React Frontend ] <---> [ FastAPI Backend ] <---> [ SQLite DB ]
                                   |
                          [ VirusTotal API ]
```

## 🧱 Technology Stack

| Layer       | Technology                | Purpose                    |
|-------------|---------------------------|----------------------------|
| Frontend    | React 18, Axios          | User interface             |
| Backend     | FastAPI, SQLAlchemy      | API server & ORM           |
| Auth        | JWT (HS256), bcrypt      | Authentication & security  |
| Database    | SQLite                   | Data persistence           |
| Analysis    | Python email parser      | Email forensics            |
| Security    | VirusTotal API           | Threat intelligence        |
| Logging     | python-json-logger       | Structured logging         |
| Deployment  | Docker, Docker Compose   | Containerization           |

## 🚀 Key Features

### 🔍 **Advanced Phishing Detection**
- Multi-factor email analysis (headers, content, URLs, attachments)
- Email forensics with routing path analysis
- Sender chain analysis and authentication validation
- Threat indicator identification

### 🛡️ **Enterprise Security**
- JWT authentication with secure token handling
- bcrypt password hashing
- Input validation with email-validator
- Rate limiting and CORS protection
- Secure, centralized error handling (no information leakage)

### 📊 **Production Monitoring**
- Structured JSON logging with correlation IDs
- Health checks and system metrics
- Performance monitoring with async operations
- Comprehensive error tracking

### 🔗 **VirusTotal Integration**
- Asynchronous API calls for non-blocking performance
- IP reputation analysis
- File scanning capabilities
- Rate limit handling

### 📈 **User Experience**
- Modern React frontend
- Real-time analysis results
- CSV and PDF export functionality (with text wrapping for long fields)
- Responsive dashboard

## 🐳 Quick Start

### Prerequisites
- Docker and Docker Compose
- VirusTotal API key (optional but recommended)

### 1. Clone and Setup
```bash
git clone <repository-url>
cd phishing_app_env_ready
```

### 2. Configure Environment
Create a `.env` file in the project root:
```env
# Security
SECRET_KEY=your_super_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=sqlite:///./database/app.db

# VirusTotal (optional)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Environment
ENV=development
```

### 3. Start the Application
```bash
docker-compose up --build
```

### 4. Access the Application
- **Frontend**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 📦 Usage

1. **Register/Login**: Create an account or sign in
2. **Upload Email**: Upload a `.eml` file for analysis
3. **View Results**: See detailed phishing analysis results
4. **Export Data**: Download CSV or PDF reports (PDF export supports text wrapping for long fields)
5. **Monitor**: Check dashboard for analysis history

## 🔧 API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User authentication

### File Analysis
- `POST /upload` - Upload and analyze .eml file
- `GET /dashboard` - Get user's analysis history
- `GET /export/csv/{email_id}` - Export analysis data as CSV
- `GET /export/pdf/{email_id}` - Export analysis data as PDF

### System
- `GET /health` - Health check endpoint
- `GET /metrics` - System metrics

## 🔍 Phishing Detection Analysis

The application performs comprehensive email analysis:

### **Email Forensics**
- Message ID extraction and validation
- Routing path analysis with hop-by-hop examination
- Timeline reconstruction from headers
- Sender chain analysis

### **Security Validation**
- SPF/DKIM authentication checks
- Header manipulation detection
- Suspicious routing pattern identification
- Authentication failure analysis

### **Content Analysis**
- URL analysis (shorteners, suspicious domains)
- Attachment examination (executables, double extensions)
- Urgency indicator detection
- Suspicious keyword identification

### **Threat Intelligence**
- VirusTotal IP reputation checks
- Sender IP analysis
- Known malicious pattern matching

## 📁 Project Structure

```
phishing_app_env_ready/
├── backend/
│   ├── api/
│   │   └── routes.py              # API endpoints
│   ├── models/
│   │   └── sqlalchemy_models.py   # Database models
│   ├── services/
│   │   ├── auth.py                # Authentication service
│   │   ├── email_forensics.py     # Email analysis
│   │   ├── phishing_detector.py   # Phishing detection
│   │   ├── upload.py              # File upload handling
│   │   └── virustotal.py          # VirusTotal integration
│   ├── utils/
│   │   ├── auth.py                # Auth utilities
│   │   ├── database.py            # Database utilities
│   │   ├── exceptions.py          # Error handling
│   │   ├── logging_config.py      # Logging configuration
│   │   └── monitoring.py          # Monitoring utilities
│   ├── init_db.py                 # Database initialization
│   └── main.py                    # FastAPI application
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── App.js                 # Main React component
│   │   └── index.js               # React entry point
│   └── package.json
├── database/                      # SQLite database files
├── docker-compose.yml             # Docker configuration
├── Dockerfile.backend             # Backend container
├── Dockerfile.frontend            # Frontend container
├── requirements.txt               # Python dependencies
└── README.md
```

## 🔒 Security Features

### **Authentication & Authorization**
- JWT-based authentication with secure token handling
- bcrypt password hashing with salt
- Token expiration and refresh mechanisms
- Role-based access control (ready for expansion)

### **Input Validation**
- Email validation using `email-validator`
- File type and size validation
- SQL injection prevention
- XSS protection

### **Error Handling**
- Centralized error handling system (custom exception classes)
- Secure error responses (no information leakage)
- Structured error logging with correlation IDs
- Graceful failure handling

### **API Security**
- CORS configuration
- Rate limiting on sensitive endpoints
- Request/response logging
- Input sanitization

## 📊 Monitoring & Logging

### **Structured Logging**
- JSON-formatted logs with correlation IDs
- Request tracing across services
- Performance metrics logging
- Error tracking with stack traces

### **Health Monitoring**
- Health check endpoints
- System metrics collection
- Performance monitoring
- Resource usage tracking

### **Log Locations**
- **Console logs**: `docker-compose logs backend`
- **File logs**: `/app/logs/app.log` (inside container)
- **Host mapping**: Add volume mapping in docker-compose.yml to access logs on your host machine

## 📝 PDF/CSV Export Improvements
- PDF and CSV exports now use robust text wrapping for long fields (e.g., hostnames, timestamps) to prevent overflow
- All tables in PDF reports automatically wrap long text using ReportLab Paragraphs
- Column widths are set for optimal readability

## 🚀 Performance Features

### **Asynchronous Operations**
- Non-blocking VirusTotal API calls (async/await)
- Thread pool for CPU-intensive tasks
- Async file processing
- Concurrent request handling

### **Optimization**
- Database connection pooling
- Caching strategies
- Efficient file handling
- Memory management

## 🛠️ Development

### **Local Development**
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python backend/init_db.py

# Start backend
cd backend && uvicorn main:app --reload

# Start frontend (in another terminal)
cd frontend && npm start
```

### **Testing**
```bash
# Test backend health
curl http://localhost:8000/health

# Test API endpoints
curl http://localhost:8000/docs
```

### **Logging**
```bash
# View backend logs
docker-compose logs backend

# View frontend logs
docker-compose logs frontend

# Follow logs in real-time
docker-compose logs -f backend
```

## 🔧 Troubleshooting

### **Common Issues**

1. **Import Errors**
   - Ensure all dependencies are installed
   - Check Python version (3.11+ recommended)
   - Verify import paths in Docker environment (PYTHONPATH is set in Dockerfile)

2. **Database Issues**
   - Run `python backend/init_db.py` to initialize database
   - Check database file permissions
   - Verify DATABASE_URL in environment

3. **Docker Issues**
   - Use `docker-compose up --build` for fresh builds
   - Check port availability (3000, 8000)
   - Verify Docker and Docker Compose versions

4. **API Issues**
   - Check CORS configuration
   - Verify JWT token validity
   - Check request/response logs

### **Performance Issues**
- Monitor container resource usage
- Check async operation logs
- Verify VirusTotal API rate limits
- Review database query performance

## 📈 Production Deployment

### **Environment Configuration**
- Set `ENV=production`
- Use strong `SECRET_KEY`
- Configure proper `DATABASE_URL`
- Set up VirusTotal API key

### **Security Checklist**
- [ ] Strong secret keys
- [ ] HTTPS configuration
- [ ] Rate limiting enabled
- [ ] Input validation active
- [ ] Error handling secure
- [ ] Logging configured
- [ ] Monitoring active

### **Scaling Considerations**
- Database connection pooling
- Load balancing
- Caching strategies
- Resource monitoring

## 📄 License

This project is for educational and development purposes. Please ensure compliance with VirusTotal API terms of service when using their API.

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs
3. Check the API documentation at `/docs`
4. Create an issue with detailed information
